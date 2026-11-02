// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HTTP+JSON LINE'S ARRIVAL: the JSON-RPC envelope the line's request spells, composed from

use std::collections::HashMap;

use serde_json::{json, Map, Value};

use crate::agent_arrival::AgentRefusal;
use crate::request_json::RequestJson;
use crate::statement::Route;

/// THE JSON-RPC ID OF A COMPOSED ENVELOPE. A JSON-RPC id is a correlation handle for a channel

pub const REST_RPC_ID: &str = "a2a-http-json";

/// THE METHOD NAMES, in A2A v1.0's spelling. Both supported revisions define HTTP+JSON;

pub mod method {
    /// `POST /message:send`.
    pub const SEND_MESSAGE: &str = "SendMessage";
    /// `POST /message:stream`.
    pub const SEND_STREAM_MESSAGE: &str = "SendStreamingMessage";
    /// `GET /tasks/{id}`.
    pub const GET_TASK: &str = "GetTask";
    /// `GET /tasks`.
    pub const LIST_TASKS: &str = "ListTasks";
    /// `POST /tasks/{id}:cancel`.
    pub const CANCEL_TASK: &str = "CancelTask";
    /// `GET /tasks/{id}:subscribe` (and `POST`).
    pub const SUBSCRIBE_TO_TASK: &str = "SubscribeToTask";
    /// `POST /tasks/{id}/pushNotificationConfigs`.
    pub const CREATE_PUSH_CONFIG: &str = "CreateTaskPushNotificationConfig";
    /// `GET /tasks/{id}/pushNotificationConfigs/{configId}`.
    pub const GET_PUSH_CONFIG: &str = "GetTaskPushNotificationConfig";
    /// `GET /tasks/{id}/pushNotificationConfigs`.
    pub const LIST_PUSH_CONFIGS: &str = "ListTaskPushNotificationConfigs";
    /// `DELETE /tasks/{id}/pushNotificationConfigs/{configId}`.
    pub const DELETE_PUSH_CONFIG: &str = "DeleteTaskPushNotificationConfig";
    /// `GET /extendedAgentCard`.
    pub const GET_EXTENDED_AGENT_CARD: &str = "GetExtendedAgentCard";
}

/// The two operations `POST /tasks/{id}:<verb>` spells. The verb is a suffix INSIDE the captured

const VERB_CANCEL: &str = "cancel";
const VERB_SUBSCRIBE: &str = "subscribe";

/// `404`: the status of a `POST /tasks/…` naming no verb this binding defines, of an arrival no

pub(crate) const STATUS_NOT_FOUND: u32 = 404;

use crate::agent_arrival::CODE_METHOD_NOT_FOUND;

/// A REQUEST'S PARAMS, built member by member, skipping what the caller did not send. Absent is
/// not empty: a query parameter the caller omitted does not appear in the composed `params`.
#[derive(Default)]
pub struct Params(Map<String, Value>);

impl Params {
    fn insert(&mut self, name: &str, value: Value) {
        if let Some(previous) = self.0.get_mut(name) {
            drop(RequestJson::new(std::mem::replace(previous, value)));
        } else {
            self.0.insert(name.to_string(), value);
        }
    }

    /// No members.
    #[must_use]
    pub fn new() -> Self {
        Self(Map::new())
    }

    /// Set `name` to a value the caller definitely supplied.
    #[must_use]
    pub fn set(mut self, name: &str, value: impl Into<Value>) -> Self {
        self.insert(name, value.into());
        self
    }

    /// Set `name` only if the caller supplied it: typed by [`json_scalar`] where the proto's field

    #[must_use]
    pub fn maybe(mut self, name: &str, value: Option<&String>) -> Self {
        if let Some(v) = value {
            let value = if TYPED_QUERY_MEMBERS.contains(&name) {
                json_scalar(v)
            } else {
                Value::String(v.clone())
            };
            self.insert(name, value);
        }
        self
    }

    /// Merge a request body in, VERBATIM (the REST body IS the `params`). A path-derived member is

    #[must_use]
    pub fn merge(mut self, body: &Value) -> Self {
        if let Some(obj) = body.as_object() {
            for (k, v) in obj {
                self.insert(k, v.clone());
            }
        }
        self
    }

    /// The members as one JSON object.
    #[must_use]
    pub fn into_value(mut self) -> Value {
        Value::Object(std::mem::take(&mut self.0))
    }
}

impl Drop for Params {
    fn drop(&mut self) {
        drop(RequestJson::new(Value::Object(std::mem::take(&mut self.0))));
    }
}

/// THE QUERY MEMBERS WHOSE PROTO FIELD IS NOT A STRING (`ListTasksRequest`'s `page_size`,

pub const TYPED_QUERY_MEMBERS: &[&str] = &["pageSize", "historyLength", "includeArtifacts"];

/// A QUERY-STRING VALUE, TYPED THE WAY THE ENVELOPE WANTS IT: an integer is a number, `true` and

#[must_use]
pub fn json_scalar(raw: &str) -> Value {
    if let Ok(n) = raw.parse::<i64>() {
        return json!(n);
    }
    match raw {
        "true" => json!(true),
        "false" => json!(false),
        other => json!(other),
    }
}

/// THE QUERY STRING AS A `name -> value` MAP, decoded as `application/x-www-form-urlencoded`

#[must_use]
pub fn query_map(query: Option<&str>) -> Option<HashMap<String, String>> {
    let mut map = HashMap::new();
    let Some(raw) = query else {
        return Some(map);
    };
    for pair in raw.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        map.insert(form_decode(k)?, form_decode(v)?);
    }
    Some(map)
}

/// Decode ONE `application/x-www-form-urlencoded` component: `+` is a space, `%XX` the byte,

#[must_use]
pub fn form_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => match (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                (Some(h), Some(l)) => {
                    out.push(h * 16 + l);
                    i += 3;
                }
                _ => {
                    out.push(bytes[i]);
                    i += 1;
                }
            },
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

/// One hex digit's value.
fn hex(b: u8) -> Option<u8> {
    (b as char).to_digit(16).and_then(|d| u8::try_from(d).ok())
}

/// One path capture, percent-decoded as the router decoded it (`%XX` is the byte; `+` stays a

#[must_use]
pub fn path_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                out.push(h * 16 + l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).ok()
}

/// A request object's `params`, or the empty object when no body was supplied. Malformed

pub fn json_body(body: &[u8]) -> Result<Value, AgentRefusal> {
    if body.is_empty() {
        return Ok(json!({}));
    }
    let document = serde_json::from_slice::<RequestJson>(body).map_err(|_| {
        AgentRefusal::new(
            crate::agent_arrival::STATUS_BAD_REQUEST,
            None,
            crate::agent_arrival::CODE_PARSE,
            crate::agent_arrival::NOT_JSON,
        )
    })?;
    if !document.is_object() {
        return Err(AgentRefusal::new(
            crate::agent_arrival::STATUS_BAD_REQUEST,
            None,
            crate::agent_arrival::CODE_INVALID_PARAMS,
            "the request body must be a JSON object",
        ));
    }
    Ok(document.into_value())
}

/// `body` less its `members`: the path names the task, so the body's spellings of it go.
fn without(body: &Value, members: &[&str]) -> Value {
    let mut body = RequestJson::new(body.clone());
    if let Some(obj) = body.as_object_mut() {
        for m in members {
            if let Some(removed) = obj.remove(*m) {
                drop(RequestJson::new(removed));
            }
        }
    }
    body.into_value()
}

/// The refusal for a `POST /tasks/…` that names no verb this binding defines: `404` +

#[must_use]
pub fn not_a_verb(addressed: &str) -> AgentRefusal {
    AgentRefusal::new(
        STATUS_NOT_FOUND,
        None,
        CODE_METHOD_NOT_FOUND,
        format!(
            "`{addressed}` names no operation on this binding; the task operations are \
             `{{id}}:{VERB_CANCEL}` and `{{id}}:{VERB_SUBSCRIBE}`"
        ),
    )
}

/// The path variables `target` binds against `route`'s pattern, by name, each decoded as the

pub fn captures(
    route: &Route,
    target: &str,
) -> Result<Option<Vec<(&'static str, String)>>, AgentRefusal> {
    let path = target.split(['?', '#']).next().unwrap_or(target);
    let want: Vec<&'static str> = route.target.split('/').collect();
    let got: Vec<&str> = path.split('/').collect();
    if want.len() != got.len() {
        return Ok(None);
    }

    if want
        .iter()
        .zip(&got)
        .any(|(&w, &g)| !(w.starts_with('{') && w.ends_with('}')) && w != g)
    {
        return Ok(None);
    }
    let mut out = Vec::new();
    for (&w, &g) in want.iter().zip(got.iter()) {
        if let Some(name) = w.strip_prefix('{').and_then(|w| w.strip_suffix('}')) {
            let value = path_decode(g).ok_or_else(|| {
                AgentRefusal::new(
                    crate::agent_arrival::STATUS_BAD_REQUEST,
                    None,
                    crate::agent_arrival::CODE_INVALID_PARAMS,
                    format!("the `{name}` path capture must decode as UTF-8"),
                )
            })?;
            out.push((name, value));
        }
    }
    Ok(Some(out))
}

/// The query string of `target`, if it has one.
fn query_of(target: &str) -> Option<&str> {
    let rest = target.split('#').next().unwrap_or(target);
    rest.split_once('?').map(|(_, q)| q)
}

/// Compose the envelope a request on the HTTP+JSON line spells: `route` is the line's route the

pub fn compose(route: &Route, target: &str, body: &[u8]) -> Result<Option<Vec<u8>>, AgentRefusal> {
    let Some(vars) = captures(route, target)? else {
        return Ok(None);
    };
    let var = |name: &str| {
        vars.iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    };
    compose_from(route, var, query_of(target), body)
}

/// [`compose`] over captures a router already decoded: `var` answers a path capture by name (the

pub fn compose_from(
    route: &Route,
    var: impl Fn(&str) -> String,
    query: Option<&str>,
    body: &[u8],
) -> Result<Option<Vec<u8>>, AgentRefusal> {
    let invalid = |message: &str| {
        AgentRefusal::new(
            crate::agent_arrival::STATUS_BAD_REQUEST,
            None,
            crate::agent_arrival::CODE_INVALID_PARAMS,
            message,
        )
    };
    let query = query_map(query).ok_or_else(|| invalid("the query must decode as UTF-8"))?;
    for (name, value) in &query {
        let valid = match name.as_str() {
            "includeArtifacts" => matches!(value.as_str(), "true" | "false"),
            "pageSize" | "historyLength" => value.parse::<i32>().is_ok(),
            _ => true,
        };
        if !valid {
            return Err(invalid(
                "a query parameter does not have its declared protobuf type",
            ));
        }
    }
    let rel = route
        .target
        .strip_prefix(crate::MOUNT_PATH)
        .unwrap_or(route.target);
    let at = |verb: &str, path: &str| route.verb == verb && rel == path;
    let (name, params) = if at("POST", crate::ROUTE_MESSAGE_SEND) {
        (method::SEND_MESSAGE, json_body(body)?)
    } else if at("POST", crate::ROUTE_MESSAGE_STREAM) {
        (method::SEND_STREAM_MESSAGE, json_body(body)?)
    } else if at("GET", crate::ROUTE_TASKS) {
        let params = Params::new()
            .maybe("contextId", query.get("contextId"))
            .maybe("status", query.get("status"))
            .maybe("pageSize", query.get("pageSize"))
            .maybe("pageToken", query.get("pageToken"))
            .maybe("historyLength", query.get("historyLength"))
            .maybe("statusTimestampAfter", query.get("statusTimestampAfter"))
            .maybe("includeArtifacts", query.get("includeArtifacts"));
        (method::LIST_TASKS, params.into_value())
    } else if at("GET", crate::ROUTE_TASK) {
        let addressed = var("id");
        match addressed.rsplit_once(':') {
            Some((id, VERB_SUBSCRIBE)) => (
                method::SUBSCRIBE_TO_TASK,
                Params::new().set("id", id).into_value(),
            ),
            _ => {
                let params = Params::new()
                    .set("id", addressed)
                    .maybe("historyLength", query.get("historyLength"));
                (method::GET_TASK, params.into_value())
            }
        }
    } else if at("POST", crate::ROUTE_TASK) {
        let addressed = var("id");
        let Some((id, verb)) = addressed.rsplit_once(':') else {
            return Err(not_a_verb(&addressed));
        };
        let name = match verb {
            VERB_CANCEL => method::CANCEL_TASK,
            VERB_SUBSCRIBE => method::SUBSCRIBE_TO_TASK,
            _ => return Err(not_a_verb(&addressed)),
        };

        let posted = RequestJson::new(if name == method::CANCEL_TASK {
            json_body(body)?
        } else {
            json!({})
        });

        let posted = RequestJson::new(without(&posted, &crate::task_identity::TASK_ID_MEMBERS));
        (
            name,
            Params::new().merge(&posted).set("id", id).into_value(),
        )
    } else if at("POST", crate::ROUTE_PUSH_CONFIGS) {
        let posted = RequestJson::new(json_body(body)?);
        let posted = RequestJson::new(without(&posted, &["task_id"]));
        let params = Params::new().merge(&posted).set("taskId", var("id"));
        (method::CREATE_PUSH_CONFIG, params.into_value())
    } else if at("GET", crate::ROUTE_PUSH_CONFIGS) {
        let params = Params::new()
            .set("taskId", var("id"))
            .maybe("pageSize", query.get("pageSize"))
            .maybe("pageToken", query.get("pageToken"));
        (method::LIST_PUSH_CONFIGS, params.into_value())
    } else if at("GET", crate::ROUTE_PUSH_CONFIG) || at("DELETE", crate::ROUTE_PUSH_CONFIG) {
        let name = if route.verb == "GET" {
            method::GET_PUSH_CONFIG
        } else {
            method::DELETE_PUSH_CONFIG
        };
        let params = Params::new()
            .set("taskId", var("id"))
            .set("id", var("config_id"));
        (name, params.into_value())
    } else if at("GET", crate::ROUTE_EXTENDED_AGENT_CARD) {
        (method::GET_EXTENDED_AGENT_CARD, json!({}))
    } else {
        return Ok(None);
    };
    let params = RequestJson::new(params);
    let bytes = zeroize::Zeroizing::new(crate::relay::json_bytes(&params).unwrap_or_default());
    Ok(Some(busbar_contract::jsonrpc::request_bytes(
        &crate::relay::json_bytes(&REST_RPC_ID).unwrap_or_default(),
        name,
        Some(bytes.as_slice()),
    )))
}

/// Re-frame a JSON-RPC answer for the HTTP+JSON line, by what it is:

#[must_use]
pub fn reframe(status: u32, body: &[u8]) -> Vec<u8> {
    use crate::answer_bytes::{is_json, member_span, result_span, with_readable};
    if !with_readable(body, is_json) {
        return body.to_vec();
    }
    if let Some(result) = result_span(body) {
        return body[result].to_vec();
    }

    match member_span(body, "error").filter(|error| body[error.start] != b'n') {
        Some(error) => {
            let Ok(error) = crate::answer_bytes::read_json(&body[error]) else {
                return body.to_vec();
            };
            let missing_message = error.get("message").and_then(Value::as_str).is_none();
            let mut document = RequestJson::new(crate::agent_arrival::aip193(status, &error));
            if missing_message {
                document["error"]["message"] =
                    "the agent returned an error without a readable message".into();
            }
            let mut bytes = crate::relay::RawBytes::default();
            serde_json::to_writer(&mut bytes, &document)
                .expect("JSON Value serialization succeeds");
            bytes.into_vec()
        }
        None => body.to_vec(),
    }
}

#[cfg(test)]
#[path = "tests/rest.rs"]
mod tests;
