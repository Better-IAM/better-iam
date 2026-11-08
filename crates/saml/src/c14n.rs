//! The canonicalizations of `xml-crypto` 6 (the TypeScript implementation's XML signature library), line by line:
//! exclusive XML canonicalization (`http://www.w3.org/2001/10/xml-exc-c14n#`, with or without comments) and
//! canonical XML 1.0 (`http://www.w3.org/TR/2001/REC-xml-c14n-20010315`, with or without comments). Their output must
//! match `xml-crypto`'s byte for byte, quirks included, or digests computed by one implementation would not verify in
//! the other.

use std::cmp::Ordering;
use std::sync::LazyLock;

use better_iam_core::js;
use icu_collator::CollatorBorrowed;
use icu_collator::options::CollatorOptions;

use crate::xml::{Document, Kind, NodeId, XMLNS_NS};

static COLLATOR: LazyLock<CollatorBorrowed<'static>> = LazyLock::new(|| {
    CollatorBorrowed::try_new(Default::default(), CollatorOptions::default())
        .expect("the root collation is compiled in")
});

/// `a.localeCompare(b)` without locales: ICU root collation.
pub fn locale_compare(a: &str, b: &str) -> Ordering {
    COLLATOR.compare(a, b)
}

/// The DSig namespace (`SignedXml.defaultNsForPrefix.ds`).
pub const DSIG_NS: &str = "http://www.w3.org/2000/09/xmldsig#";

/// A namespace declaration found on an ancestor (`{ prefix, namespaceURI }`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NsDecl {
    pub prefix: String,
    pub uri: String,
}

/// The options `getCanonXml` hands a canonicalization.
#[derive(Debug, Clone, Default)]
pub struct C14nOptions {
    pub inclusive_prefixes: Vec<String>,
    pub ancestor_namespaces: Vec<NsDecl>,
}

/// A failed canonicalization (`Unable to ... canonicalize node type: N`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct C14nError(pub String);

fn default_ns_for_prefix(prefix: &str) -> Option<String> {
    (prefix == "ds").then(|| DSIG_NS.to_owned())
}

/// `encodeSpecialCharactersInText`.
pub fn encode_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\r' => out.push_str("&#xD;"),
            other => out.push(other),
        }
    }
    out
}

/// `encodeSpecialCharactersInAttribute`.
pub fn encode_attribute(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '"' => out.push_str("&quot;"),
            '\r' => out.push_str("&#xD;"),
            '\n' => out.push_str("&#xA;"),
            '\t' => out.push_str("&#x9;"),
            other => out.push(other),
        }
    }
    out
}

fn node_type(kind: &Kind) -> u8 {
    match kind {
        Kind::Element(_) => 1,
        Kind::Text(_) => 3,
        Kind::CData(_) => 4,
        Kind::Pi { .. } => 7,
        Kind::Comment(_) => 8,
        Kind::Document => 9,
        Kind::DocType { .. } => 10,
    }
}

/// `renderComment`.
fn render_comment(document: &Document, id: NodeId, data: &str, with_comments: bool) -> String {
    if !with_comments {
        return String::new();
    }
    let mut before = false;
    let mut after = false;
    if document.parent(id) == Some(Document::ROOT) {
        let siblings = document.children(Document::ROOT);
        let root = document.document_element();
        let position = siblings.iter().position(|node| *node == id).unwrap_or(0);
        before = siblings[position..].iter().any(|node| Some(*node) == root);
        after = siblings[..=position].iter().any(|node| Some(*node) == root);
    }
    format!(
        "{}<!--{}-->{}",
        if after { "\n" } else { "" },
        encode_text(data),
        if before { "\n" } else { "" }
    )
}

/// The `data` of a character-data node (`node.data`), when it has one.
fn data_of(kind: &Kind) -> Option<&str> {
    match kind {
        Kind::Text(text) | Kind::CData(text) | Kind::Comment(text) => Some(text),
        Kind::Pi { data, .. } => Some(data),
        _ => None,
    }
}

/// `attrCompare`: attributes without a namespace first, then by namespace URI + local name.
fn attr_compare(a: &crate::xml::Attr, b: &crate::xml::Attr) -> Ordering {
    let truthy =
        |namespace: &Option<String>| namespace.as_deref().is_some_and(|uri| !uri.is_empty());
    if !truthy(&a.namespace) && truthy(&b.namespace) {
        return Ordering::Less;
    }
    if !truthy(&b.namespace) && truthy(&a.namespace) {
        return Ordering::Greater;
    }
    let key = |attr: &crate::xml::Attr| {
        format!(
            "{}{}",
            attr.namespace
                .clone()
                .unwrap_or_else(|| "undefined".to_owned()),
            attr.local
        )
    };
    js::cmp_utf16(&key(a), &key(b))
}

/// `renderAttrs`: every attribute but namespace declarations, sorted.
fn render_attrs(document: &Document, id: NodeId) -> String {
    let Some(element) = document.element(id) else {
        return String::new();
    };
    let mut attrs: Vec<&crate::xml::Attr> = element
        .attrs
        .iter()
        .filter(|attr| !attr.name.starts_with("xmlns"))
        .collect();
    attrs.sort_by(|a, b| attr_compare(a, b));
    let mut out = String::new();
    for attr in attrs {
        out.push(' ');
        out.push_str(&attr.name);
        out.push_str("=\"");
        out.push_str(&encode_attribute(&attr.value));
        out.push('"');
    }
    out
}

fn sort_namespaces<T>(list: &mut [(String, T)]) {
    list.sort_by(|a, b| {
        if a.0 == b.0 {
            Ordering::Equal
        } else {
            locale_compare(&a.0, &b.0)
        }
    });
}

// --- exclusive canonicalization ----------------------------------------------------------------------------------

/// A prefix in scope with the namespace it was rendered with (`{ prefix, namespaceURI }`; None is `undefined`).
type ScopedPrefix = (String, Option<String>);

fn in_scope(scope: &[ScopedPrefix], prefix: &str, uri: &Option<String>) -> bool {
    scope
        .iter()
        .any(|(declared, namespace)| declared == prefix && namespace == uri)
}

/// `ExclusiveCanonicalization.renderNs`.
fn exclusive_render_ns(
    document: &Document,
    id: NodeId,
    scope: &mut Vec<ScopedPrefix>,
    default_ns: &Option<String>,
    inclusive: &[String],
) -> (String, Option<String>) {
    let element = document.element(id).expect("an element");
    let mut out = String::new();
    let mut new_default = default_ns.clone();
    let mut list: Vec<(String, Option<String>)> = Vec::new();
    let current = element.namespace.clone().unwrap_or_default();
    if let Some(prefix) = element
        .prefix
        .as_deref()
        .filter(|prefix| !prefix.is_empty())
    {
        let uri = element
            .namespace
            .clone()
            .or_else(|| default_ns_for_prefix(prefix));
        if !in_scope(scope, prefix, &uri) {
            list.push((prefix.to_owned(), uri.clone()));
            scope.push((prefix.to_owned(), uri));
        }
    } else if default_ns.as_deref() != Some(current.as_str()) {
        new_default = element.namespace.clone();
        out.push_str(" xmlns=\"");
        out.push_str(element.namespace.as_deref().unwrap_or_default());
        out.push('"');
    }
    for attr in &element.attrs {
        if attr
            .prefix
            .as_deref()
            .is_some_and(|prefix| !prefix.is_empty())
        {
            let value = Some(attr.value.clone());
            if !in_scope(scope, &attr.local, &value) && inclusive.contains(&attr.local) {
                list.push((attr.local.clone(), value.clone()));
                scope.push((attr.local.clone(), value));
            }
            let prefix = attr.prefix.clone().unwrap_or_default();
            if !in_scope(scope, &prefix, &attr.namespace) && prefix != "xmlns" && prefix != "xml" {
                list.push((prefix.clone(), attr.namespace.clone()));
                scope.push((prefix, attr.namespace.clone()));
            }
        }
    }
    sort_namespaces(&mut list);
    for (prefix, uri) in list {
        out.push_str(" xmlns:");
        out.push_str(&prefix);
        out.push_str("=\"");
        out.push_str(uri.as_deref().unwrap_or_default());
        out.push('"');
    }
    (out, new_default)
}

fn exclusive_inner(
    document: &Document,
    id: NodeId,
    scope: &mut Vec<ScopedPrefix>,
    default_ns: &Option<String>,
    inclusive: &[String],
    with_comments: bool,
) -> Result<String, C14nError> {
    let kind = document.kind(id);
    if let Kind::Comment(data) = kind {
        return Ok(render_comment(document, id, data, with_comments));
    }
    if let Some(data) = data_of(kind).filter(|data| !data.is_empty()) {
        return Ok(encode_text(data));
    }
    let Kind::Element(element) = kind else {
        return Err(C14nError(format!(
            "Unable to exclusive canonicalize node type: {}",
            node_type(kind)
        )));
    };
    let (rendered, new_default) = exclusive_render_ns(document, id, scope, default_ns, inclusive);
    let mut out = format!(
        "<{}{}{}>",
        element.name,
        rendered,
        render_attrs(document, id)
    );
    for child in document.children(id) {
        let mut copy = scope.clone();
        out.push_str(&exclusive_inner(
            document,
            *child,
            &mut copy,
            &new_default,
            inclusive,
            with_comments,
        )?);
    }
    out.push_str("</");
    out.push_str(&element.name);
    out.push('>');
    Ok(out)
}

/// `ExclusiveCanonicalization.process(elem, options)`: may add the inclusive prefixes' ancestor declarations to
/// `elem` (a clone), as `xml-crypto` does.
pub fn exclusive(
    document: &mut Document,
    id: NodeId,
    options: &C14nOptions,
    with_comments: bool,
) -> Result<String, C14nError> {
    let mut inclusive = options.inclusive_prefixes.clone();
    if inclusive.is_empty()
        && let Some(method) = document
            .find_children(id, None, "CanonicalizationMethod")
            .first()
        && let Some(namespaces) = document
            .find_children(*method, None, "InclusiveNamespaces")
            .first()
    {
        inclusive = document
            .attr(*namespaces, "PrefixList")
            .unwrap_or_default()
            .split(' ')
            .map(str::to_owned)
            .collect();
    }
    if !inclusive.is_empty() {
        for prefix in &inclusive {
            for ancestor in &options.ancestor_namespaces {
                if *prefix == ancestor.prefix {
                    document.set_attribute_ns(
                        id,
                        Some(XMLNS_NS),
                        &format!("xmlns:{prefix}"),
                        &ancestor.uri,
                    );
                }
            }
        }
    }
    let mut scope = Vec::new();
    exclusive_inner(
        document,
        id,
        &mut scope,
        &Some(String::new()),
        &inclusive,
        with_comments,
    )
}

// --- canonical XML 1.0 ----------------------------------------------------------------------------------------------

fn inclusive_render_ns(
    document: &Document,
    id: NodeId,
    scope: &mut Vec<String>,
    default_ns: &str,
    ancestors: &[NsDecl],
) -> (String, String) {
    let element = document.element(id).expect("an element");
    let mut out = String::new();
    let mut new_default = default_ns.to_owned();
    let mut list: Vec<(String, String)> = Vec::new();
    let current = element.namespace.clone().unwrap_or_default();
    if let Some(prefix) = element
        .prefix
        .as_deref()
        .filter(|prefix| !prefix.is_empty())
    {
        if !scope.iter().any(|declared| declared == prefix) {
            let uri = element
                .namespace
                .clone()
                .or_else(|| default_ns_for_prefix(prefix))
                .unwrap_or_default();
            list.push((prefix.to_owned(), uri));
            scope.push(prefix.to_owned());
        }
    } else if default_ns != current {
        new_default = current.clone();
        out.push_str(" xmlns=\"");
        out.push_str(&new_default);
        out.push('"');
    }
    for attr in &element.attrs {
        if attr.prefix.as_deref() == Some("xmlns") && !scope.contains(&attr.local) {
            list.push((attr.local.clone(), attr.value.clone()));
            scope.push(attr.local.clone());
        }
        if let Some(prefix) = attr.prefix.as_deref().filter(|prefix| !prefix.is_empty())
            && !scope.iter().any(|declared| declared == prefix)
            && prefix != "xmlns"
            && prefix != "xml"
        {
            list.push((
                prefix.to_owned(),
                attr.namespace.clone().unwrap_or_default(),
            ));
            scope.push(prefix.to_owned());
        }
    }
    for ancestor in ancestors {
        if !list
            .iter()
            .any(|(prefix, uri)| *prefix == ancestor.prefix && *uri == ancestor.uri)
        {
            list.push((ancestor.prefix.clone(), ancestor.uri.clone()));
        }
    }
    sort_namespaces(&mut list);
    for (prefix, uri) in list {
        if prefix.is_empty() {
            out.push_str(&format!(" xmlns=\"{uri}\""));
        } else {
            out.push_str(&format!(" xmlns:{prefix}=\"{uri}\""));
        }
    }
    (out, new_default)
}

fn inclusive_inner(
    document: &Document,
    id: NodeId,
    scope: &mut Vec<String>,
    default_ns: &str,
    ancestors: &[NsDecl],
    with_comments: bool,
) -> Result<String, C14nError> {
    let kind = document.kind(id);
    if let Kind::Comment(data) = kind {
        return Ok(render_comment(document, id, data, with_comments));
    }
    if let Some(data) = data_of(kind).filter(|data| !data.is_empty()) {
        return Ok(encode_text(data));
    }
    let Kind::Element(element) = kind else {
        return Err(C14nError(format!(
            "Unable to canonicalize node type: {}",
            node_type(kind)
        )));
    };
    let (rendered, new_default) = inclusive_render_ns(document, id, scope, default_ns, ancestors);
    let mut out = format!(
        "<{}{}{}>",
        element.name,
        rendered,
        render_attrs(document, id)
    );
    for child in document.children(id) {
        let mut copy = scope.clone();
        out.push_str(&inclusive_inner(
            document,
            *child,
            &mut copy,
            &new_default,
            &[],
            with_comments,
        )?);
    }
    out.push_str("</");
    out.push_str(&element.name);
    out.push('>');
    Ok(out)
}

/// `C14nCanonicalization.process(node, options)`.
pub fn inclusive(
    document: &Document,
    id: NodeId,
    options: &C14nOptions,
    with_comments: bool,
) -> Result<String, C14nError> {
    let mut scope: Vec<String> = options
        .ancestor_namespaces
        .iter()
        .map(|ns| ns.prefix.clone())
        .collect();
    inclusive_inner(
        document,
        id,
        &mut scope,
        "",
        &options.ancestor_namespaces,
        with_comments,
    )
}

/// `findAncestorNs` for the element an XPath selected (None when it selected nothing): the namespace declarations
/// of its ancestors (nearest first, one per prefix), without the prefix the element itself declares or uses.
pub fn find_ancestor_ns(document: &Document, node: Option<NodeId>) -> Vec<NsDecl> {
    let Some(node) = node else {
        return Vec::new();
    };
    let strip = |name: &str| -> String {
        let rest = &name["xmlns".len()..];
        rest.strip_prefix(':').unwrap_or(rest).to_owned()
    };
    let mut collected: Vec<NsDecl> = Vec::new();
    let mut current = document.parent(node);
    while let Some(parent) = current {
        let Some(element) = document.element(parent) else {
            break;
        };
        for attr in &element.attrs {
            if attr.name.starts_with("xmlns") {
                collected.push(NsDecl {
                    prefix: strip(&attr.name),
                    uri: attr.value.clone(),
                });
            }
        }
        current = document.parent(parent);
    }
    let mut unique: Vec<NsDecl> = Vec::new();
    for ns in collected {
        if !unique.iter().any(|existing| existing.prefix == ns.prefix) {
            unique.push(ns);
        }
    }
    let own = document
        .element(node)
        .and_then(|element| {
            element
                .attrs
                .iter()
                .find(|attr| attr.name.starts_with("xmlns"))
                .map(|attr| strip(&attr.name))
        })
        .or_else(|| {
            document
                .element(node)
                .map(|element| element.prefix.clone().unwrap_or_default())
        })
        .unwrap_or_default();
    unique.into_iter().filter(|ns| ns.prefix != own).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exc(xml: &str) -> String {
        let source = Document::parse(xml).unwrap();
        let root = source.document_element().unwrap();
        let (mut clone, id) = source.clone_subtree(root);
        exclusive(&mut clone, id, &C14nOptions::default(), false).unwrap()
    }

    #[test]
    fn exclusive_canonicalization() {
        assert_eq!(
            exc(
                "<p:a xmlns:p=\"urn:p\" xmlns:q=\"urn:q\" z=\"1\" b=\"&#10;\"><p:b/><!--x-->t&gt;\r</p:a>"
            ),
            "<p:a xmlns:p=\"urn:p\" b=\"&#xA;\" z=\"1\"><p:b></p:b>t&gt;\n</p:a>"
        );
        assert_eq!(
            exc("<a xmlns=\"urn:d\"><b xmlns:x=\"urn:x\" x:y=\"1\"/></a>"),
            "<a xmlns=\"urn:d\"><b xmlns:x=\"urn:x\" x:y=\"1\"></b></a>"
        );
    }

    #[test]
    fn canonical_xml_renders_declarations() {
        let source = Document::parse("<a xmlns:p=\"urn:p\"><p:b xmlns:q=\"urn:q\"/></a>").unwrap();
        let root = source.document_element().unwrap();
        let child = source.child_elements(root)[0];
        let ancestors = find_ancestor_ns(&source, Some(child));
        assert_eq!(
            ancestors,
            vec![NsDecl {
                prefix: "p".into(),
                uri: "urn:p".into()
            }]
        );
        let (clone, id) = source.clone_subtree(child);
        let options = C14nOptions {
            ancestor_namespaces: ancestors,
            ..C14nOptions::default()
        };
        assert_eq!(
            inclusive(&clone, id, &options, false).unwrap(),
            "<p:b xmlns:p=\"urn:p\" xmlns:q=\"urn:q\"></p:b>"
        );
    }
}
