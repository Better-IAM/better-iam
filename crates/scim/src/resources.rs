//! Port of `packages/scim/src/resources.ts`: SCIM responses, resource rendering, and the discovery documents.

use std::sync::LazyLock;

use better_iam_core::{IamResult, Record, js as core_js};
use bytes::Bytes;
use serde_json::{Map, Value, json};

use crate::js::{encode_uri_component, iso_string, js_string, truthy};
use crate::types::{
    BULK_MAX_OPERATIONS, ENTERPRISE_SCHEMA, GROUP_SCHEMA, LIST_SCHEMA, MAX_PAYLOAD_SIZE,
    ObjectValue, USER_SCHEMA,
};

/// A buffered HTTP response.
pub type HttpResponse = http::Response<Bytes>;

/// An HTTP response with headers (later headers replace earlier ones of the same name).
pub fn http_response(
    status: u16,
    body: Option<String>,
    headers: &[(&str, String)],
) -> HttpResponse {
    let mut response = http::Response::new(body.map(Bytes::from).unwrap_or_default());
    *response.status_mut() =
        http::StatusCode::from_u16(status).unwrap_or(http::StatusCode::INTERNAL_SERVER_ERROR);
    for (name, value) in headers {
        if let (Ok(name), Ok(value)) = (
            http::HeaderName::from_bytes(name.as_bytes()),
            http::HeaderValue::from_str(value),
        ) {
            response.headers_mut().insert(name, value);
        }
    }
    response
}

/// `response(body, status, headers)`: an `application/scim+json` answer, never cached; 204 and 304 have no body.
pub fn response(body: &Value, status: u16, headers: &[(&str, String)]) -> HttpResponse {
    let mut all: Vec<(&str, String)> = vec![
        ("content-type", "application/scim+json".to_owned()),
        ("cache-control", "no-store".to_owned()),
    ];
    all.extend(headers.iter().cloned());
    let body = (status != 204 && status != 304).then(|| core_js::stringify(body));
    http_response(status, body, &all)
}

/// `listResponse(resources, totalResults, startIndex)`.
pub fn list_response(resources: Vec<Value>, total_results: usize, start_index: f64) -> Value {
    let count = resources.len();
    json!({
        "schemas": [LIST_SCHEMA],
        "totalResults": total_results,
        "startIndex": crate::js::number(start_index),
        "itemsPerPage": count,
        "Resources": resources,
    })
}

fn put(map: &mut Map<String, Value>, key: &str, value: Option<&Value>) {
    if let Some(value) = value {
        map.insert(key.to_owned(), value.clone());
    }
}

fn meta(link: &Record, resource_type: &str, location: String) -> IamResult<Value> {
    Ok(json!({
        "resourceType": resource_type,
        "created": iso_string(link.get("createdAt"))?,
        "lastModified": iso_string(link.get("updatedAt"))?,
        "version": format!("W/\"{}\"", js_string(link.get("version"))),
        "location": location,
    }))
}

/// `userResource(link, base)`.
pub fn user_resource(link: &Record, base: &str) -> IamResult<ObjectValue> {
    let enterprise = link.get("enterprise").filter(|value| truthy(Some(value)));
    let mut map = Map::new();
    map.insert(
        "schemas".into(),
        if enterprise.is_some() {
            json!([USER_SCHEMA, ENTERPRISE_SCHEMA])
        } else {
            json!([USER_SCHEMA])
        },
    );
    put(&mut map, "id", link.get("id"));
    put(&mut map, "externalId", link.get("externalId"));
    put(&mut map, "userName", link.get("userName"));
    put(&mut map, "displayName", link.get("displayName"));
    put(&mut map, "active", link.get("active"));
    put(&mut map, "emails", link.get("emails"));
    put(&mut map, "name", link.get("name"));
    put(&mut map, "title", link.get("title"));
    if let Some(enterprise) = enterprise {
        map.insert(ENTERPRISE_SCHEMA.into(), enterprise.clone());
    }
    let id = js_string(link.get("id"));
    map.insert(
        "meta".into(),
        meta(
            link,
            "User",
            format!("{base}/Users/{}", encode_uri_component(&id)),
        )?,
    );
    Ok(map)
}

/// `groupResource(link, base)`.
pub fn group_resource(link: &Record, base: &str) -> IamResult<ObjectValue> {
    let mut map = Map::new();
    map.insert("schemas".into(), json!([GROUP_SCHEMA]));
    put(&mut map, "id", link.get("id"));
    put(&mut map, "externalId", link.get("externalId"));
    put(&mut map, "displayName", link.get("displayName"));
    let members: Vec<Value> = match link.get("members") {
        Some(Value::Array(items)) => items
            .iter()
            .map(|value| {
                json!({
                    "value": value,
                    "$ref": format!("{base}/Users/{}", encode_uri_component(&js_string(Some(value)))),
                    "type": "User",
                })
            })
            .collect(),
        _ => Vec::new(),
    };
    map.insert("members".into(), Value::Array(members));
    let id = js_string(link.get("id"));
    map.insert(
        "meta".into(),
        meta(
            link,
            "Group",
            format!("{base}/Groups/{}", encode_uri_component(&id)),
        )?,
    );
    Ok(map)
}

/// `serviceProviderConfig`: the discovery document describes exactly the implemented subset: filtering, sorting,
/// PATCH, bulk, ETags, pagination; no password changes.
pub static SERVICE_PROVIDER_CONFIG: LazyLock<Value> = LazyLock::new(|| {
    json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
        "patch": { "supported": true },
        "bulk": { "supported": true, "maxOperations": BULK_MAX_OPERATIONS, "maxPayloadSize": MAX_PAYLOAD_SIZE },
        "filter": { "supported": true, "maxResults": 200 },
        "changePassword": { "supported": false },
        "sort": { "supported": true },
        "etag": { "supported": true },
        "authenticationSchemes": [
            {
                "type": "oauthbearertoken",
                "name": "Scoped SCIM bearer token",
                "description": "Connection-scoped bearer token",
                "specUri": "https://www.rfc-editor.org/rfc/rfc6750",
                "primary": true,
            }
        ],
    })
});

/// `attribute(name, overrides)`: defaults first, overrides replacing them in place and adding the rest.
fn attribute(name: &str, overrides: Value) -> Value {
    let mut map = Map::new();
    map.insert("name".into(), json!(name));
    map.insert("type".into(), json!("string"));
    map.insert("multiValued".into(), json!(false));
    map.insert("required".into(), json!(false));
    map.insert("mutability".into(), json!("readWrite"));
    map.insert("returned".into(), json!("default"));
    if let Value::Object(overrides) = overrides {
        for (key, value) in overrides {
            map.insert(key, value);
        }
    }
    Value::Object(map)
}

/// Default attributes of the given names.
fn plain(names: &[&str]) -> Vec<Value> {
    names
        .iter()
        .map(|name| attribute(name, json!({})))
        .collect()
}

/// `resourceTypeDocuments`.
pub static RESOURCE_TYPE_DOCUMENTS: LazyLock<Vec<Value>> = LazyLock::new(|| {
    ["User", "Group"]
        .iter()
        .map(|name| {
            let mut map = Map::new();
            map.insert(
                "schemas".into(),
                json!(["urn:ietf:params:scim:schemas:core:2.0:ResourceType"]),
            );
            map.insert("id".into(), json!(name));
            map.insert("name".into(), json!(name));
            map.insert("endpoint".into(), json!(format!("/{name}s")));
            map.insert(
                "schema".into(),
                json!(if *name == "User" {
                    USER_SCHEMA
                } else {
                    GROUP_SCHEMA
                }),
            );
            if *name == "User" {
                map.insert(
                    "schemaExtensions".into(),
                    json!([{ "schema": ENTERPRISE_SCHEMA, "required": false }]),
                );
            }
            Value::Object(map)
        })
        .collect()
});

/// `schemaDocuments`.
pub static SCHEMA_DOCUMENTS: LazyLock<Vec<Value>> = LazyLock::new(|| {
    let mut user_attributes: Vec<Value> =
        ["userName", "displayName", "externalId", "active", "title"]
            .iter()
            .map(|name| {
                attribute(
                    name,
                    json!({
                        "type": if *name == "active" { "boolean" } else { "string" },
                        "required": *name == "userName",
                        "uniqueness": if *name == "userName" { "server" } else { "none" },
                        "caseExact": *name == "externalId",
                    }),
                )
            })
            .collect();
    user_attributes.push(attribute(
        "name",
        json!({
            "type": "complex",
            "subAttributes": plain(&[
                "formatted",
                "familyName",
                "givenName",
                "middleName",
                "honorificPrefix",
                "honorificSuffix",
            ]),
        }),
    ));
    let email_attributes: Vec<Value> = ["value", "type", "display", "primary"]
        .iter()
        .map(|name| {
            attribute(
                name,
                json!({
                    "type": if *name == "primary" { "boolean" } else { "string" },
                    "required": *name == "value",
                }),
            )
        })
        .collect();
    user_attributes.push(attribute(
        "emails",
        json!({
            "type": "complex",
            "multiValued": true,
            "subAttributes": email_attributes,
        }),
    ));
    let mut enterprise_attributes: Vec<Value> = [
        "employeeNumber",
        "costCenter",
        "organization",
        "division",
        "department",
    ]
    .iter()
    .map(|name| attribute(name, json!({})))
    .collect();
    enterprise_attributes.push(attribute(
        "manager",
        json!({
            "type": "complex",
            "subAttributes": plain(&["value", "displayName", "$ref"]),
        }),
    ));
    let group_attributes = vec![
        attribute(
            "displayName",
            json!({ "required": true, "uniqueness": "none" }),
        ),
        attribute(
            "members",
            json!({
                "type": "complex",
                "multiValued": true,
                "subAttributes": [
                    {
                        "name": "value",
                        "type": "string",
                        "required": true,
                        "mutability": "immutable",
                        "returned": "default",
                    }
                ],
            }),
        ),
    ];
    let schema = "urn:ietf:params:scim:schemas:core:2.0:Schema";
    vec![
        json!({ "id": USER_SCHEMA, "name": "User", "schemas": [schema], "attributes": user_attributes }),
        json!({
            "id": ENTERPRISE_SCHEMA,
            "name": "EnterpriseUser",
            "schemas": [schema],
            "attributes": enterprise_attributes,
        }),
        json!({ "id": GROUP_SCHEMA, "name": "Group", "schemas": [schema], "attributes": group_attributes }),
    ]
});
