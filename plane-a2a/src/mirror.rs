// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Busbar's own callback, mirrored onto the agent (sent over the agent's need from the local

use serde_json::{json, Value};

use crate::binding::Binding;
use crate::local::LocalVerb;
use crate::request_json::RequestJson;

/// Canonical internal method names; [`request`] renders them in the declared wire version.
pub mod method {
    /// Create (or replace) a task's push config.
    pub const CREATE_PUSH_CONFIG: &str = "CreateTaskPushNotificationConfig";
    /// Read one.
    pub const GET_PUSH_CONFIG: &str = "GetTaskPushNotificationConfig";
    /// List a task's.
    pub const LIST_PUSH_CONFIGS: &str = "ListTaskPushNotificationConfigs";
    /// Delete one.
    pub const DELETE_PUSH_CONFIG: &str = "DeleteTaskPushNotificationConfig";
}

/// The id every busbar-originated request carries: busbar originated the hop, so there is no

pub const ORIGINATED_RPC_ID: &str = "busbar-originated";

/// The verb busbar issues when a caller uses `verb`; `None` for a local verb that mirrors onto

#[must_use]
pub fn mirrored_verb(verb: LocalVerb) -> Option<&'static str> {
    Some(match verb {
        LocalVerb::CreatePushConfig(_) => method::CREATE_PUSH_CONFIG,
        LocalVerb::GetPushConfig(_) => method::GET_PUSH_CONFIG,
        LocalVerb::ListPushConfigs(_) => method::LIST_PUSH_CONFIGS,
        LocalVerb::DeletePushConfig(_) => method::DELETE_PUSH_CONFIG,
        LocalVerb::ListTasks | LocalVerb::Subscribe => return None,
    })
}

/// Busbar's own callback address for `public_url`, or `None` where busbar offers none: no

#[must_use]
pub fn callback_url(public_url: &str) -> Option<String> {
    let url = url::Url::parse(public_url).ok()?;
    if url.scheme() != "https" {
        return None;
    }
    crate::a2a::public::absolute(public_url, &crate::mounted_route(crate::PUSH_PATH_SUFFIX))
}

/// The id of the one config busbar registers for the agent's task `backend_task`.
#[must_use]
pub fn config_id(backend_task: &str) -> String {
    format!("busbar-{backend_task}")
}

/// A create naming busbar's own callback.
#[must_use]
pub fn create_params(backend_task: &str, url: &str, token: &str) -> Value {
    json!({
        "taskId": backend_task,
        "id": config_id(backend_task),
        "url": url,
        "authentication": { "scheme": crate::push::TOKEN_SCHEME, "credentials": token },
    })
}

/// The params `method` is issued with: a list names the task, a get or delete busbar's config.
#[must_use]
pub fn params_for(method: &str, backend_task: &str, create: &Value) -> Value {
    match method {
        method::CREATE_PUSH_CONFIG => create.clone(),
        method::LIST_PUSH_CONFIGS => json!({ "taskId": backend_task }),
        _ => json!({ "taskId": backend_task, "id": config_id(backend_task) }),
    }
}

/// One originated request, framed for the agent's binding as a relayed one is: its verb, target,

#[must_use]
pub fn request(
    binding: Binding,
    url: &str,
    version: &'static str,
    method: &str,
    params: &Value,
) -> Option<busbar_contract::abi::sdk::exchange::Request> {
    use crate::relay::{From, HopRelay, Piece, PieceAnswer};
    let translated = if binding == Binding::JsonRpc && version == "0.3" {
        let (method, params) = v03_request(method, params)?;
        Some((method, RequestJson::new(params)))
    } else {
        None
    };
    let (method, params) = translated
        .as_ref()
        .map_or((method, params), |(method, params)| (*method, &**params));
    let envelope = RequestJson::new(json!({
        "jsonrpc": "2.0",
        "id": ORIGINATED_RPC_ID,
        "method": method,
        "params": params,
    }));
    let mut body = crate::relay::RawBytes::default();
    serde_json::to_writer(&mut body, &envelope).ok()?;
    let mut relay = HopRelay::new(Value::String(ORIGINATED_RPC_ID.into()), version);
    relay.bind(binding, &envelope);
    let piece = |from| Piece {
        from,
        bytes: &body,
        status: None,
        last: false,
    };
    let PieceAnswer::Attempt(attempt) = relay.on_piece(piece(From::Kernel(Some(url)))) else {
        return None;
    };
    let body = match relay.on_piece(piece(From::Caller)) {
        PieceAnswer::ToFarEnd(bytes) => bytes,
        PieceAnswer::ToFarEndLent => body.clone(),

        PieceAnswer::Nothing => crate::relay::RawBytes::default(),
        _ => return None,
    };
    Some(busbar_contract::abi::sdk::exchange::Request {
        method: attempt.verb.as_bytes().to_vec(),
        target: attempt.target.into_bytes(),
        fields: attempt
            .fields
            .into_iter()
            .map(|(n, v)| (n.as_bytes().to_vec(), v.into_owned().into_bytes()))
            .collect(),
        body: body.into_vec(),
        timeout_ms: 0,
    })
}

/// The four mirrored v0.3 JSON-RPC operations, rendered from the canonical internal params.
fn v03_request<'a>(method: &'a str, params: &Value) -> Option<(&'a str, Value)> {
    let wire_method = match method {
        method::CREATE_PUSH_CONFIG => "tasks/pushNotificationConfig/set",
        method::GET_PUSH_CONFIG => "tasks/pushNotificationConfig/get",
        method::LIST_PUSH_CONFIGS => "tasks/pushNotificationConfig/list",
        method::DELETE_PUSH_CONFIG => "tasks/pushNotificationConfig/delete",
        _ => return Some((method, params.clone())),
    };
    let task = params.get("taskId")?.as_str()?;
    let params = match method {
        method::CREATE_PUSH_CONFIG => {
            let mut config = RequestJson::new(Value::Object(params.as_object()?.clone()));
            drop(
                config
                    .as_object_mut()?
                    .remove("taskId")
                    .map(RequestJson::new),
            );
            if let Some(auth) = config
                .get_mut("authentication")
                .and_then(Value::as_object_mut)
            {
                if let Some(scheme) = auth.remove("scheme") {
                    let scheme = RequestJson::new(scheme);
                    drop(
                        auth.insert("schemes".to_string(), json!([scheme]))
                            .map(RequestJson::new),
                    );
                }
            }
            json!({"taskId": task, "pushNotificationConfig": config})
        }
        method::LIST_PUSH_CONFIGS => json!({"id": task}),
        _ => json!({"id": task, "pushNotificationConfigId": params.get("id")?.as_str()?}),
    };
    Some((wire_method, params))
}

/// THE ANSWER TO ONE ORIGINATED REQUEST, as the readers below read it: its status and body as the

#[must_use]
pub fn answered(
    binding: Binding,
    method: &str,
    status: u16,
    body: Vec<u8>,
) -> Option<(u16, Vec<u8>)> {
    if binding != Binding::Grpc {
        return Some((status, body));
    }
    let body = crate::relay::RawBytes::from(body);
    let rpc = crate::framed::Rpc::of_method(method)?;
    let (len, _) = crate::framed::take_message(&body).ok()??;
    let message = &body[crate::framed::MESSAGE_PREFIX..crate::framed::MESSAGE_PREFIX + len];
    let result = RequestJson::new(crate::framed::response_result(rpc, message).ok()?);
    let mut rendered = crate::relay::RawBytes::default();
    serde_json::to_writer(&mut rendered, &result).ok()?;
    Some((
        200,
        busbar_contract::jsonrpc::result_bytes(
            &crate::relay::json_bytes(&ORIGINATED_RPC_ID).unwrap_or_default(),
            &rendered,
        ),
    ))
}

/// A request busbar originates that made no hop: the agent's `upstream_credential`, re-resolved for
/// it, is unavailable, so the host sent nothing. Nothing follows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unleased;

/// What one originated request came to: its status and body (`None` when it was not answered),

pub type Landed = Result<Option<(u16, Vec<u8>)>, Unleased>;

/// What one originated request came to, out of its exchange's `answer`: the status and body

pub fn landed(
    binding: Binding,
    agent: &str,
    method: &str,
    answer: Result<
        busbar_contract::abi::sdk::exchange::ExchangeResponse,
        busbar_contract::abi::sdk::conn::ConnFailure,
    >,
) -> Landed {
    use busbar_contract::abi::sdk::conn::ConnFailure;
    match answer {
        Err(ConnFailure::CredentialUnavailable) => {
            busbar_contract::diag_warn!(
                crate::diagnostics::A2A_OUTBOUND_CRED_UNLEASED,
                agent = %agent,
                "a2a: the outbound credential could not be leased"
            );
            Err(Unleased)
        }
        Err(_) => {
            tracing::warn!(
                agent = %agent,
                method,
                phase = "transport",
                failure_class = "connector",
                "A2A originated request was not answered; the local result is unchanged"
            );
            Ok(None)
        }
        Ok(reply) => Ok(answered(binding, method, reply.status, reply.body)),
    }
}

/// Whether a read's answer leaves busbar's registration drifted (gone at the agent): an answer that

#[must_use]
pub fn drifted(binding: Binding, answered: Option<(u16, &[u8])>, config_id: &str) -> bool {
    let Some((status, body)) = answered else {
        return true;
    };
    if !(200..300).contains(&status) {
        return true;
    }
    let id = Value::String(ORIGINATED_RPC_ID.into());
    let envelope = crate::relay::RawBytes::from(
        match binding {
            Binding::HttpJson => crate::answer_bytes::rewrap(body, &id).ok(),

            Binding::JsonRpc | Binding::Grpc => Some(body.to_vec()),
        }
        .unwrap_or_default(),
    );
    let envelope = serde_json::from_slice::<RequestJson>(&envelope).ok();
    !envelope
        .as_ref()
        .and_then(|v| v.get("result"))
        .is_some_and(|r| holds_config(r, config_id))
}

/// Whether `found` holds the config `config_id`, compared whole on its `id` member: a config itself

fn holds_config(found: &Value, config_id: &str) -> bool {
    match found {
        Value::Array(items) => items.iter().any(|i| holds_config(i, config_id)),
        Value::Object(member) => {
            member.get("id").and_then(Value::as_str) == Some(config_id)
                || ["pushNotificationConfig", "configs"]
                    .iter()
                    .any(|m| member.get(*m).is_some_and(|v| holds_config(v, config_id)))
        }
        _ => false,
    }
}

/// Where a mirror stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// The mirrored verb is to be (or is being) issued.
    Mirror,
    /// A read found busbar's registration gone: the create is to be (or is being) issued.
    Rearm,
    /// Nothing more to issue.
    Done,
}

/// ONE REQUEST BUSBAR ORIGINATES to an agent, across its piece's PENDING entries: the agent (its

pub struct Originated {
    /// The agent's registration name: the dial names it ([`Exchange::as_member`]).
    pub agent: String,
    /// The agent's url.
    pub url: String,
    /// Its registration's `allow_private`.
    pub allow_private: bool,
    /// The binding its held card speaks.
    pub binding: Binding,
    /// The version the request declares.
    pub version: &'static str,
    /// The handle the next host call takes.
    pub seq: u32,
    /// The request in flight: the handle it counts on from, and its exchange.
    pub exchange: Option<(u32, Box<busbar_contract::abi::sdk::exchange::Exchange>)>,
}

impl std::fmt::Debug for Originated {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Originated")
            .field("agent", &self.agent)
            .field("seq", &self.seq)
            .field("in_flight", &self.exchange.is_some())
            .finish_non_exhaustive()
    }
}

/// ONE MIRROR: where it stands, the verb it mirrors, the agent's own id for the task, the create a

pub struct Flight {
    /// Where it stands.
    pub stage: Stage,
    /// The mirrored verb.
    pub method: &'static str,
    /// The agent's own id for the task.
    pub backend_task: String,
    /// The create, for a re-arm.
    pub create: Value,
    /// The requests.
    pub hop: Originated,
}

impl std::fmt::Debug for Flight {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Flight")
            .field("stage", &self.stage)
            .field("method", &self.method)
            .field("backend_task", &self.backend_task)
            .field("hop", &self.hop)
            .finish_non_exhaustive()
    }
}

impl Drop for Flight {
    fn drop(&mut self) {
        drop(RequestJson::new(std::mem::take(&mut self.create)));
    }
}

impl Flight {
    /// The verb this stage issues.
    #[must_use]
    pub fn issuing(&self) -> &'static str {
        match self.stage {
            Stage::Rearm => method::CREATE_PUSH_CONFIG,
            _ => self.method,
        }
    }

    /// The params this stage issues.
    #[must_use]
    pub fn params(&self) -> Value {
        params_for(self.issuing(), &self.backend_task, &self.create)
    }

    /// The stage after this one's request came to `landed`: an [`Unleased`] request ends the mirror

    pub fn land(&mut self, landed: Result<Option<(u16, &[u8])>, Unleased>) {
        match landed {
            Err(Unleased) => self.stage = Stage::Done,
            Ok(answered) => self.advance(answered),
        }
    }

    /// The stage after this one's request was answered (`answered` = its status and body, `None`

    pub fn advance(&mut self, answered: Option<(u16, &[u8])>) {
        self.stage = match self.stage {
            Stage::Mirror => {
                let read = matches!(
                    self.method,
                    method::GET_PUSH_CONFIG | method::LIST_PUSH_CONFIGS
                );
                if read && drifted(self.hop.binding, answered, &config_id(&self.backend_task)) {
                    Stage::Rearm
                } else {
                    Stage::Done
                }
            }
            Stage::Rearm | Stage::Done => Stage::Done,
        };
    }
}

/// `ListTasks`, as busbar issues it to refresh its own rows from the agent: no paging members, the agent's default page.
pub const LIST_TASKS: &str = "ListTasks";

/// WHAT A LISTING TAUGHT BUSBAR: for each entry of the agent's answer whose id is the agent's own

#[must_use]
pub fn listed_states(
    binding: Binding,
    answered: Option<(u16, &[u8])>,
    ours: &std::collections::BTreeMap<String, String>,
) -> Vec<(String, crate::a2a::task::TaskState)> {
    let Some((status, body)) = answered else {
        return Vec::new();
    };
    if !(200..300).contains(&status) {
        return Vec::new();
    }
    let id = Value::String(ORIGINATED_RPC_ID.into());
    let envelope = crate::relay::RawBytes::from(
        match binding {
            Binding::HttpJson => crate::answer_bytes::rewrap(body, &id).ok(),

            Binding::JsonRpc | Binding::Grpc => Some(body.to_vec()),
        }
        .unwrap_or_default(),
    );
    let envelope = serde_json::from_slice::<RequestJson>(&envelope).ok();
    let Some(result) = envelope.as_ref().and_then(|v| v.get("result")) else {
        return Vec::new();
    };
    let listed = result
        .get("tasks")
        .and_then(Value::as_array)
        .or_else(|| result.as_array())
        .map(Vec::as_slice)
        .unwrap_or_default();
    listed
        .iter()
        .filter_map(|entry| {
            let busbar = ours.get(entry.get("id")?.as_str()?)?;
            let state = entry
                .pointer("/status/state")
                .and_then(Value::as_str)
                .and_then(crate::task_identity::wire_state)?;
            Some((busbar.clone(), state))
        })
        .collect()
}

#[cfg(test)]
#[path = "tests/mirror_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/mirror_legs_tests.rs"]
mod legs_tests;

#[cfg(test)]
#[path = "tests/mirror_unleased_tests.rs"]
mod unleased_tests;
