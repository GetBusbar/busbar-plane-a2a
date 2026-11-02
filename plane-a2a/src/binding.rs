// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The outbound binding: which of A2A's bindings a hop speaks to an agent, read off the agent's

use serde_json::Value;
use zeroize::Zeroizing;

use crate::request_json::RequestJson;
use crate::task_identity::TASK_ID_MEMBERS;

/// The JSON-RPC binding's card word.
pub const BINDING_JSONRPC: &str = "JSONRPC";
/// The HTTP+JSON binding's card word.
pub const BINDING_HTTP_JSON: &str = "HTTP+JSON";
/// The gRPC binding's card word.
pub const BINDING_GRPC: &str = "GRPC";

/// The JSON-RPC binding's name, as the Statement and a published card spell it lower-cased.
pub const BINDING_DOCUMENT: &str = "jsonrpc";
/// The HTTP+JSON binding's lower-cased name.
pub const BINDING_TARGET: &str = "http+json";
/// The gRPC binding's lower-cased name.
pub const BINDING_FRAMED: &str = "grpc";

/// A binding the plane frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Binding {
    /// JSON-RPC: the caller's bytes, verbatim.
    #[default]
    JsonRpc,
    /// HTTP+JSON (A2A section 11.3): the operation's request line, its params as the body.
    HttpJson,
    /// gRPC: the rpc's path under the service, its params as the rpc's request message, carried
    /// over the grpc transport ([`crate::statement::NEED_GRPC`]).
    Grpc,
}

impl Binding {
    /// The card word this binding answers to.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Binding::JsonRpc => BINDING_JSONRPC,
            Binding::HttpJson => BINDING_HTTP_JSON,
            Binding::Grpc => BINDING_GRPC,
        }
    }
}

/// The lookup: the binding a card word names, if the plane frames it: an unknown word is `None`, and the hop is refused naming it.
#[must_use]
pub fn speakable(word: &str) -> Option<Binding> {
    match word.trim().to_ascii_uppercase().as_str() {
        BINDING_JSONRPC => Some(Binding::JsonRpc),
        BINDING_HTTP_JSON => Some(Binding::HttpJson),
        BINDING_GRPC => Some(Binding::Grpc),
        _ => None,
    }
}

/// A transport choice for the operator's unchanged endpoint.
pub struct Selected<'a> {
    /// The configured endpoint, unchanged: advertised URLs are compared, never dialled.
    pub endpoint: &'a str,
    /// The card's binding word; an unsupported word remains explicit for refusal.
    pub word: String,
}

/// Select HOW the configured endpoint speaks without changing WHERE the operator sends it.
#[must_use]
pub fn select<'a>(card: Option<&Value>, configured_url: &'a str) -> Selected<'a> {
    let word = match card {
        Some(card) => match card.get("supportedInterfaces").and_then(Value::as_array) {
            Some(interfaces) => {
                let words: Vec<&str> = interfaces
                    .iter()
                    .filter_map(|i| i.get("protocolBinding").and_then(Value::as_str))
                    .filter(|word| !word.trim().is_empty())
                    .collect();
                interfaces
                    .iter()
                    .find_map(|interface| {
                        let word = interface.get("protocolBinding")?.as_str()?;
                        (speakable(word).is_some()
                            && endpoint_matches(configured_url, interface.get("url")?.as_str()?))
                        .then_some(word)
                    })
                    .or_else(|| words.iter().copied().find(|word| speakable(word).is_some()))
                    .or_else(|| words.first().copied())
                    .unwrap_or(BINDING_JSONRPC)
                    .to_string()
            }
            None => {
                let preferred = match card.get("preferredTransport") {
                    None | Some(Value::Null) => BINDING_JSONRPC,
                    Some(value) => value.as_str().unwrap_or("INVALID"),
                };
                let primary_matches = card
                    .get("url")
                    .and_then(Value::as_str)
                    .is_none_or(|url| endpoint_matches(configured_url, url));
                if primary_matches && speakable(preferred).is_some() {
                    preferred.to_string()
                } else {
                    card.get("additionalInterfaces")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                        .find_map(|interface| {
                            let word = interface.get("transport")?.as_str()?;
                            (speakable(word).is_some()
                                && endpoint_matches(
                                    configured_url,
                                    interface.get("url")?.as_str()?,
                                ))
                            .then_some(word)
                        })
                        .unwrap_or(preferred)
                        .to_string()
                }
            }
        },
        None => BINDING_JSONRPC.to_string(),
    };
    Selected {
        endpoint: configured_url,
        word,
    }
}

/// Compare resolved URL references using the existing URL parser alone. Query order, path
fn endpoint_matches(configured_url: &str, advertised: &str) -> bool {
    if advertised.is_empty() {
        return false;
    }
    let Ok(configured) = url::Url::parse(configured_url) else {
        return false;
    };
    configured
        .join(advertised)
        .is_ok_and(|resolved| resolved == configured)
}

/// The binding at the card's primary endpoint. Consumers with an operator endpoint use
#[cfg(test)]
#[must_use]
pub fn binding_of(card: Option<&Value>) -> String {
    let endpoint = card
        .and_then(|card| card.get("url"))
        .and_then(Value::as_str)
        .unwrap_or("");
    select(card, endpoint).word
}

/// One untrusted word made safe for a caller's error body: at most 48 characters of an
#[must_use]
pub fn bounded_word(word: &str) -> String {
    const MAX: usize = 48;
    let mut out: String = word
        .chars()
        .take(MAX)
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+' | '/') {
                c
            } else {
                '?'
            }
        })
        .collect();
    if out.is_empty() {
        out.push('?');
    }
    out
}

/// The stable token of a hop the plane cannot frame.
pub const UNFRAMABLE_CODE: &str = "a2a.hop.unframable";

/// The caller's sentence for `method` that cannot be carried over `binding`.
#[must_use]
pub fn unframable_text(method: &str, binding: &str) -> String {
    format!(
        "{UNFRAMABLE_CODE}: `{}` could not be carried to this agent over its `{}` binding",
        bounded_word(method),
        bounded_word(binding),
    )
}

/// One operation's place on the HTTP+JSON binding: its request line, the `params` members its query
struct RestOp {
    verb: &'static str,
    path: &'static str,
    query: &'static [&'static str],
    body: bool,
}

/// The HTTP+JSON row of `method`, from either A2A dialect's spelling.
fn rest_op(method: &str) -> Option<RestOp> {
    let (verb, path, query, body): (_, _, &'static [&'static str], _) = match method {
        "SendMessage" | "message/send" => ("POST", "/message:send", &[], true),
        "SendStreamingMessage" | "message/stream" => ("POST", "/message:stream", &[], true),
        "GetTask" | "tasks/get" => ("GET", "/tasks/{id}", &["historyLength"], false),
        "ListTasks" | "tasks/list" => (
            "GET",
            "/tasks",
            &[
                "contextId",
                "status",
                "pageSize",
                "pageToken",
                "historyLength",
                "statusTimestampAfter",
                "includeArtifacts",
            ],
            false,
        ),
        "CancelTask" | "tasks/cancel" => ("POST", "/tasks/{id}:cancel", &[], true),
        "SubscribeToTask" | "tasks/resubscribe" => ("GET", "/tasks/{id}:subscribe", &[], false),
        "CreateTaskPushNotificationConfig" | "tasks/pushNotificationConfig/set" => {
            ("POST", "/tasks/{taskId}/pushNotificationConfigs", &[], true)
        }
        "ListTaskPushNotificationConfigs" | "tasks/pushNotificationConfig/list" => (
            "GET",
            "/tasks/{taskId}/pushNotificationConfigs",
            &["pageSize", "pageToken"],
            false,
        ),
        "GetTaskPushNotificationConfig" | "tasks/pushNotificationConfig/get" => (
            "GET",
            "/tasks/{taskId}/pushNotificationConfigs/{id}",
            &[],
            false,
        ),
        "DeleteTaskPushNotificationConfig" | "tasks/pushNotificationConfig/delete" => (
            "DELETE",
            "/tasks/{taskId}/pushNotificationConfigs/{id}",
            &[],
            false,
        ),
        "GetExtendedAgentCard" | "agent/getAuthenticatedExtendedCard" => {
            ("GET", "/extendedAgentCard", &[], false)
        }
        _ => return None,
    };
    Some(RestOp {
        verb,
        path,
        query,
        body,
    })
}

/// One HTTP+JSON request: its verb, its target under the agent's origin, whether it carries a
/// document, and the document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Framed {
    /// The request line's verb.
    pub verb: &'static str,
    /// The path and query, under the agent's origin.
    pub target: String,
    /// The request carries a body (and so a `content-type`).
    pub has_body: bool,
    /// The body.
    pub body: Vec<u8>,
}

impl Drop for Framed {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        #[cfg(test)]
        crate::tests::raw_custody_probe::before_wipe(&self.body);
        self.body.as_mut_slice().zeroize();
        #[cfg(test)]
        crate::tests::raw_custody_probe::after_wipe(&self.body);
        self.body.zeroize();
    }
}

/// COMPOSE `method` with `params` on the HTTP+JSON binding under the agent URL `base` (A2A section
pub fn compose(base: &str, method: &str, params: &Value) -> Result<Framed, String> {
    let op = rest_op(method).ok_or_else(|| {
        format!("`{method}` is not one of the eleven operations A2A's HTTP+JSON binding defines")
    })?;
    let base = url::Url::parse(base).map_err(|e| format!("the agent URL does not parse: {e}"))?;
    let mut remaining = RequestJson::new(Value::Object(
        params
            .as_object()
            .ok_or_else(|| format!("`{method}` params must be an object"))?
            .clone(),
    ));
    let left = remaining
        .as_object_mut()
        .expect("an object was constructed");
    let mut path = String::new();

    if let Some(tenant) = left.remove("tenant") {
        let tenant = RequestJson::new(tenant);
        let tenant = Zeroizing::new(if tenant.is_null() {
            String::new()
        } else {
            scalar(&tenant)
        });
        if tenant.as_str() == "." || tenant.as_str() == ".." {
            return Err(format!(
                "`{method}`'s `tenant` is a dot segment, which would re-point the request line"
            ));
        }
        if !tenant.is_empty() {
            path.push('/');
            path.push_str(&percent(&tenant));
        }
    }
    let mut rest = op.path;
    while let Some(open) = rest.find('{') {
        path.push_str(&rest[..open]);
        let close = rest[open..]
            .find('}')
            .ok_or_else(|| format!("the route template `{}` is malformed", op.path))?
            + open;
        let name = &rest[open + 1..close];

        let spellings: &[&str] = match name {
            "id" if !op.path.contains("{taskId}") => &TASK_ID_MEMBERS,
            "taskId" => &["taskId", "task_id"],
            _ => &[],
        };
        let value = spellings
            .iter()
            .find_map(|s| left.remove(*s))
            .or_else(|| left.remove(name))
            .ok_or_else(|| format!("`{method}` names no `{name}` to address"))?;
        let value = RequestJson::new(value);
        let value = value
            .as_str()
            .ok_or_else(|| format!("`{method}`'s `{name}` must be a string"))?;
        if value.is_empty() {
            return Err(format!("`{method}`'s `{name}` is empty"));
        }

        if value == "." || value == ".." {
            return Err(format!(
                "`{method}`'s `{name}` is a dot segment, which would re-point the request line"
            ));
        }
        path.push_str(&percent(value));
        rest = &rest[close + 1..];
    }
    path.push_str(rest);
    let mut url = base.clone();
    url.set_path(&format!("{}{path}", base.path().trim_end_matches('/')));
    {
        let mut query = url.query_pairs_mut();
        for name in op.query {
            if let Some(value) = left.remove(*name) {
                let value = RequestJson::new(value);
                if !value.is_null() {
                    query.append_pair(name, &Zeroizing::new(scalar(&value)));
                }
            }
        }
    }
    if url.query() == Some("") {
        url.set_query(None);
    }
    if !op.body && !left.is_empty() {
        let mut names: Vec<&String> = left.keys().collect();
        names.sort();
        return Err(format!(
            "`{method}` carries {names:?}, which A2A's HTTP+JSON binding has nowhere to put on a \
             `{}` request",
            op.verb
        ));
    }
    let body = if op.body {
        crate::relay::json_bytes(&remaining)
            .map_err(|e| format!("the request params could not be rendered: {e}"))?
    } else {
        Vec::new()
    };
    let mut target = url.path().to_string();
    if let Some(query) = url.query() {
        target.push('?');
        target.push_str(query);
    }
    Ok(Framed {
        verb: op.verb,
        target,
        has_body: op.body,
        body,
    })
}

/// A query-string value: a string as itself, anything else as its JSON rendering.
fn scalar(value: &Value) -> String {
    value
        .as_str()
        .map_or_else(|| value.to_string(), str::to_string)
}

/// Percent-encode one path segment against an allowlist, so no `/`, `?`, `#` or `%` in an id can
fn percent(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for b in raw.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[cfg(test)]
#[path = "tests/binding_tests.rs"]
mod tests;
