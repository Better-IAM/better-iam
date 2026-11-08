//! The objects `xml2js` (as Node-SAML configures it: `explicitRoot`, `explicitCharkey`, prefixes stripped from
//! element names) builds from XML, built from a DOM subtree: `{ "$": { attributes }, "_": "text", "Child": [ ... ] }`,
//! with whitespace-only text dropped and an empty element as its (whitespace) text. Node-SAML reads assertions from
//! these objects.

use serde_json::{Map, Value};

use crate::xml::{Document, Kind, NodeId, is_js_space};

/// `processors.stripPrefix`: everything up to the last `:` removed, except for names starting with `xmlns`.
pub fn strip_prefix(name: &str) -> &str {
    if name.starts_with("xmlns") {
        return name;
    }
    match name.rfind(':') {
        Some(index) => &name[index + 1..],
        None => name,
    }
}

fn element_value(document: &Document, id: NodeId) -> Result<Value, String> {
    let element = document.element(id).expect("an element");
    let mut object = Map::new();
    let mut text = String::new();
    let mut cdata = false;
    object.insert("_".into(), Value::Null);
    if !element.attrs.is_empty() {
        let mut attributes = Map::new();
        for attr in &element.attrs {
            attributes.insert(attr.name.clone(), Value::String(attr.value.clone()));
        }
        object.insert("$".into(), Value::Object(attributes));
    }
    for child in document.children(id) {
        match document.kind(*child) {
            Kind::Element(child_element) => {
                let name = strip_prefix(&child_element.name).to_owned();
                if name == "_" {
                    return Err("obj[charkey].match is not a function".to_owned());
                }
                let value = element_value(document, *child)?;
                match object.get_mut(&name) {
                    Some(Value::Array(items)) => items.push(value),
                    Some(existing) => {
                        let previous = existing.take();
                        *existing = Value::Array(vec![previous, value]);
                    }
                    None => {
                        object.insert(name, Value::Array(vec![value]));
                    }
                }
            }
            Kind::Text(data) => text.push_str(data),
            Kind::CData(data) => {
                text.push_str(data);
                cdata = true;
            }
            _ => {}
        }
    }
    let whitespace = text.chars().all(is_js_space);
    if whitespace && !cdata {
        object.shift_remove("_");
    } else {
        object.insert("_".into(), Value::String(text.clone()));
    }
    Ok(if object.is_empty() {
        Value::String(text)
    } else {
        Value::Object(object)
    })
}

/// `parseXml2JsFromString(element.toString())`: `{ RootName: value }`.
pub fn to_xml2js(document: &Document, id: NodeId) -> Result<Value, String> {
    let element = document.element(id).expect("an element");
    let mut root = Map::new();
    root.insert(
        strip_prefix(&element.name).to_owned(),
        element_value(document, id)?,
    );
    Ok(Value::Object(root))
}
