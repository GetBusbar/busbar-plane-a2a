// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE VERBS THE PLANE ANSWERS ITSELF, over the task store ([`crate::tasks`]): `ListTasks`, the
//! push-notification config CRUD, and the two refusals of `SubscribeToTask`.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::a2a::task::{Task, TaskState};
use crate::agent_arrival::AgentRefusal;
use crate::push::DeliveryAuth;
use crate::records::KIND_PUSH_CONFIG;
use crate::tasks::{self, task_key, Halt, Records, Write};
use busbar_contract::abi::sdk::cred::Cred;
use zeroize::{Zeroize, Zeroizing};

/// WHICH SPELLING OF THE PUSH-CONFIG VERBS A CALLER USED: v0.3 nests the config under
/// `pushNotificationConfig`, v1.0 flattens it, so the dialect decides the envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dialect {
    /// A2A v0.3: `tasks/pushNotificationConfig/*`.
    V03,
    /// A2A v1.0: `*TaskPushNotificationConfig`.
    V10,
}

impl Dialect {
    /// The version a JSON-RPC method name is spelled in: v0.3's are slash paths
    /// (`message/send`, `tasks/pushNotificationConfig/set`), v1.0's are PascalCase
    /// (`SendMessage`, `CreateTaskPushNotificationConfig`).
    #[must_use]
    pub fn of_method(method: &str) -> Self {
        if method.contains('/') {
            Dialect::V03
        } else {
            Dialect::V10
        }
    }

    /// The version token a callback is registered under ([`PushConfig::version`]).
    #[must_use]
    pub const fn version(self) -> &'static str {
        match self {
            Dialect::V03 => "0.3",
            Dialect::V10 => "1.0",
        }
    }
}

/// A verb this plane answers WITHOUT a backend hop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalVerb {
    /// `ListTasks`.
    ListTasks,
    /// Create (or replace) the task's push config.
    CreatePushConfig(Dialect),
    /// Read it back.
    GetPushConfig(Dialect),
    /// List it.
    ListPushConfigs(Dialect),
    /// Delete it.
    DeletePushConfig(Dialect),
    /// Only the two refusals are local; see [`subscribe_refusal`].
    Subscribe,
}

/// The local verb `method` names, listed rather than pattern-matched.
#[must_use]
pub fn verb_of(method: &str) -> Option<LocalVerb> {
    Some(match method {
        "ListTasks" | "tasks/list" => LocalVerb::ListTasks,
        "CreateTaskPushNotificationConfig" => LocalVerb::CreatePushConfig(Dialect::V10),
        "tasks/pushNotificationConfig/set" => LocalVerb::CreatePushConfig(Dialect::V03),
        "GetTaskPushNotificationConfig" => LocalVerb::GetPushConfig(Dialect::V10),
        "tasks/pushNotificationConfig/get" => LocalVerb::GetPushConfig(Dialect::V03),
        "ListTaskPushNotificationConfigs" => LocalVerb::ListPushConfigs(Dialect::V10),
        "tasks/pushNotificationConfig/list" => LocalVerb::ListPushConfigs(Dialect::V03),
        "DeleteTaskPushNotificationConfig" => LocalVerb::DeletePushConfig(Dialect::V10),
        "tasks/pushNotificationConfig/delete" => LocalVerb::DeletePushConfig(Dialect::V03),
        "SubscribeToTask" | "tasks/resubscribe" => LocalVerb::Subscribe,
        _ => return None,
    })
}

/// The host's reach the verbs need beyond the records: the destination judge.
pub trait Reach: Records {
    /// `dest.judge` of `dest` under the open-web class, its name resolved and private reach
    /// refused whatever the deployment's private-address setting: a `DEST_*` verdict.
    ///
    /// # Errors
    /// [`Halt`].
    fn judge(&mut self, dest: &str) -> Result<u64, Halt>;
}

/// One local answer: its status and its JSON body.
#[derive(Clone, PartialEq, Eq)]
pub struct LocalAnswer {
    /// The status.
    pub status: u32,
    /// The body.
    pub body: Vec<u8>,
}

impl Drop for LocalAnswer {
    fn drop(&mut self) {
        self.body.zeroize();
    }
}
impl std::fmt::Debug for LocalAnswer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalAnswer")
            .field("status", &self.status)
            .field("body", &"<redacted>")
            .finish()
    }
}

use crate::agent_arrival::{
    CODE_INTERNAL as INTERNAL, CODE_INVALID_PARAMS as INVALID_PARAMS,
    CODE_TASK_NOT_FOUND as TASK_NOT_FOUND, CODE_UNSUPPORTED_OPERATION as UNSUPPORTED_OPERATION,
};

/// The refusal every verb gives for a task id it does not hold for this caller: one string, so the
/// verbs cannot drift into different existence oracles.
pub const NO_SUCH_TASK: &str = "no task with that id is open for this caller";

/// A JSON-RPC success under the caller's id.
fn ok(rpc_id: &Value, result: Value) -> LocalAnswer {
    let result = crate::request_json::RequestJson::new(result);
    let id_bytes = Zeroizing::new(serde_json::to_vec(rpc_id).unwrap_or_default());
    let result_bytes = Zeroizing::new(serde_json::to_vec(&*result).unwrap_or_default());
    LocalAnswer {
        status: 200,
        body: busbar_contract::jsonrpc::result_bytes(&id_bytes, &result_bytes),
    }
}

/// A JSON-RPC error under the caller's id, at the status A2A section 5.4 binds to its code.
fn refusal(rpc_id: &Value, code: i64, message: impl Into<String>) -> AgentRefusal {
    AgentRefusal::new(
        match code {
            TASK_NOT_FOUND => 404,
            UNSUPPORTED_OPERATION | INVALID_PARAMS => 400,
            _ => 500,
        },
        Some(rpc_id.clone()),
        code,
        message.into(),
    )
}

/// [`refusal`], as the verb's answer.
fn err(rpc_id: &Value, code: i64, message: impl Into<String>) -> LocalAnswer {
    let refused = refusal(rpc_id, code, message);
    LocalAnswer {
        status: refused.status,
        body: serde_json::to_vec(&refused.envelope()).unwrap_or_default(),
    }
}

/// The words when the store would not take a push config's registration.
pub const CONFIG_UNRECORDED: &str = "the push notification config could not be recorded";

/// The words when the store would not take a push config's removal: the config stays and the
/// caller retries.
pub const CONFIG_UNDELETED: &str =
    "the push notification config could not be deleted; retry the delete";

/// The answer when the store refuses verb `verb`'s own record write: the internal error (`500`,
/// `-32603`) echoing `rpc_id`, or `None` for a verb whose answer does not depend on a write.
#[must_use]
pub fn unrecorded(verb: LocalVerb, rpc_id: &Value) -> Option<AgentRefusal> {
    Some(refusal(rpc_id, INTERNAL, unrecorded_message(verb)?))
}

fn unrecorded_message(verb: LocalVerb) -> Option<&'static str> {
    Some(match verb {
        LocalVerb::CreatePushConfig(_) => CONFIG_UNRECORDED,
        LocalVerb::DeletePushConfig(_) => CONFIG_UNDELETED,
        _ => return None,
    })
}

/// The same durable-write refusal when its exact conditional receipt answers the local verb.
pub(crate) fn unrecorded_answer(verb: LocalVerb, rpc_id: &Value) -> Option<LocalAnswer> {
    Some(err(rpc_id, INTERNAL, unrecorded_message(verb)?))
}

/// The answer when the task store could not be reached: JSON-RPC's internal error.
#[must_use]
pub fn unreadable(rpc_id: &Value) -> LocalAnswer {
    err(rpc_id, INTERNAL, "the task store could not be reached")
}

/// ANSWER local verb `verb` of `envelope` for `caller` at `now`; its writes go to `out`. `None`
/// when the answer is not the plane's (a subscribe to a live task).
///
/// # Errors
/// [`Halt::Pending`] when a records call pends; nothing is written then.
pub fn answer_local(
    reach: &mut dyn Reach,
    verb: LocalVerb,
    envelope: &Value,
    caller: &str,
    now: u64,
    out: &mut Vec<Write>,
) -> Result<Option<LocalAnswer>, Halt> {
    let rpc_id = envelope.get("id").unwrap_or(&Value::Null);
    let params = envelope.get("params").unwrap_or(&Value::Null);
    let push_dialect = match verb {
        LocalVerb::CreatePushConfig(d)
        | LocalVerb::GetPushConfig(d)
        | LocalVerb::ListPushConfigs(d)
        | LocalVerb::DeletePushConfig(d) => Some(d),
        _ => None,
    };
    if push_dialect.is_some_and(|dialect| addressed_id(dialect, params).is_none()) {
        return Ok(Some(err(
            rpc_id,
            INVALID_PARAMS,
            "a push notification config request must name its task with a string id",
        )));
    }
    let answered = match verb {
        LocalVerb::ListTasks => list_tasks(reach, params, rpc_id, caller, now)?,
        LocalVerb::CreatePushConfig(d) => {
            create_push_config(reach, d, params, rpc_id, caller, now, out)?
        }
        LocalVerb::GetPushConfig(d) => get_push_config(reach, d, params, rpc_id, caller, now)?,
        LocalVerb::ListPushConfigs(d) => list_push_configs(reach, d, params, rpc_id, caller, now)?,
        LocalVerb::DeletePushConfig(d) => {
            delete_push_config(reach, d, params, rpc_id, caller, now, out)?
        }
        LocalVerb::Subscribe => return subscribe_refusal(reach, params, rpc_id, caller, now),
    };
    Ok(Some(answered))
}

/// `ListTasks`'s answer over `rec` (the refreshed rows, seen through the piece's own writes).
///
/// # Errors
/// [`Halt`].
pub(crate) fn list_answer(
    rec: &mut dyn Records,
    envelope: &Value,
    caller: &str,
    now: u64,
) -> Result<LocalAnswer, Halt> {
    let rpc_id = envelope.get("id").unwrap_or(&Value::Null);
    let params = envelope.get("params").unwrap_or(&Value::Null);
    list_tasks(rec, params, rpc_id, caller, now)
}

/// The protocol's spelling of a task state (the `TASK_STATE_*` tokens of the A2A v1.0 schema).
#[must_use]
pub fn wire_state(state: TaskState) -> &'static str {
    match state {
        TaskState::Submitted => "TASK_STATE_SUBMITTED",
        TaskState::Working => "TASK_STATE_WORKING",
        TaskState::InputRequired => "TASK_STATE_INPUT_REQUIRED",
        TaskState::AuthRequired => "TASK_STATE_AUTH_REQUIRED",
        TaskState::Completed => "TASK_STATE_COMPLETED",
        TaskState::Failed => "TASK_STATE_FAILED",
        TaskState::Canceled => "TASK_STATE_CANCELED",
        TaskState::Rejected => "TASK_STATE_REJECTED",
    }
}

/// One task row as an A2A `Task`: id, context and state, and nothing busbar does not hold.
#[must_use]
pub fn task_json(task: &Task) -> Value {
    json!({
        "id": task.task_id,
        "contextId": task.context_id,
        "status": { "state": wire_state(task.state) },
    })
}

/// The page size a caller that asks for none gets.
pub const DEFAULT_PAGE_SIZE: usize = 50;
/// The largest page size: `ListTasksRequest.page_size` "The maximum value is 100" (a2a.proto); a
/// caller asking for more gets this many.
pub const MAX_PAGE_SIZE: usize = 100;

/// An integer that arrives as a number or, per the schema's `anyOf`, as a decimal string.
fn as_int(v: Option<&Value>) -> Option<i64> {
    match v? {
        Value::Number(n) => n.as_i64(),
        Value::String(s) => s.parse().ok(),
        _ => None,
    }
}

/// A member under its camelCase or its snake_case spelling.
fn member<'a>(params: &'a Value, camel: &str, snake: &str) -> Option<&'a Value> {
    params.get(camel).or_else(|| params.get(snake))
}

/// THE PAGE CURSOR: the sort key of the last row returned, `"<updated_at>:<task_id>"`.
#[must_use]
pub fn cursor_of(task: &Task) -> String {
    format!("{}:{}", task.updated_at, task.task_id)
}

/// `ListTasks`: the caller's own rows, filtered, newest first, one page.
fn list_tasks(
    rec: &mut dyn Records,
    params: &Value,
    rpc_id: &Value,
    caller: &str,
    now: u64,
) -> Result<LocalAnswer, Halt> {
    let context_id = member(params, "contextId", "context_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let wanted = match params.get("status").filter(|v| !v.is_null()) {
        None => None,
        Some(Value::String(value)) if value == "TASK_STATE_UNSPECIFIED" => None,
        Some(Value::Number(value)) if value.as_i64() == Some(0) => None,
        Some(value) => {
            let state = match value {
                Value::String(value) => TaskState::parse(
                    value
                        .strip_prefix("TASK_STATE_")
                        .map_or_else(
                            || value.clone(),
                            |v| v.to_ascii_lowercase().replace('_', "-"),
                        )
                        .as_str(),
                )
                .ok(),
                Value::Number(value) => match value.as_i64() {
                    Some(1) => Some(TaskState::Submitted),
                    Some(2) => Some(TaskState::Working),
                    Some(3) => Some(TaskState::Completed),
                    Some(4) => Some(TaskState::Failed),
                    Some(5) => Some(TaskState::Canceled),
                    Some(6) => Some(TaskState::InputRequired),
                    Some(7) => Some(TaskState::Rejected),
                    Some(8) => Some(TaskState::AuthRequired),
                    _ => None,
                },
                _ => None,
            };
            let Some(state) = state else {
                return Ok(err(
                    rpc_id,
                    INVALID_PARAMS,
                    "`status` must name an A2A task state",
                ));
            };
            Some(state)
        }
    };
    if member(params, "pageSize", "page_size")
        .filter(|v| !v.is_null())
        .is_some_and(|v| as_int(Some(v)).is_none_or(|n| n < 0))
    {
        return Ok(err(
            rpc_id,
            INVALID_PARAMS,
            "`pageSize` must be a non-negative integer",
        ));
    }
    let page_size = as_int(member(params, "pageSize", "page_size"))
        .and_then(|n| usize::try_from(n).ok())
        .filter(|n| *n > 0)
        .unwrap_or(DEFAULT_PAGE_SIZE)
        .min(MAX_PAGE_SIZE);
    let token = match member(params, "pageToken", "page_token").filter(|v| !v.is_null()) {
        None => "",
        Some(Value::String(token))
            if token.is_empty()
                || token.split_once(':').is_some_and(|(ts, id)| {
                    !id.is_empty()
                        && !ts.is_empty()
                        && ts.bytes().all(|b| b.is_ascii_digit())
                        && ts.parse::<u64>().is_ok()
                }) =>
        {
            token
        }
        _ => {
            return Ok(err(
                rpc_id,
                INVALID_PARAMS,
                "`pageToken` is not a task page cursor",
            ))
        }
    };

    let since = match member(params, "statusTimestampAfter", "status_timestamp_after")
        .filter(|v| !v.is_null())
    {
        None => None,
        Some(v) => match v.as_str().map(str::parse::<crate::wkt::Timestamp>) {
            Some(Ok(t)) => Some(i128::from(t.seconds) * 1_000_000_000 + i128::from(t.nanos)),
            _ => {
                return Ok(err(
                    rpc_id,
                    INVALID_PARAMS,
                    "`statusTimestampAfter` must be an RFC 3339 timestamp, such as \
                     `2023-10-27T10:00:00Z`",
                ))
            }
        },
    };

    let mut rows: Vec<Task> = tasks::list(rec, caller, now)?
        .iter()
        .map(|r| Task::from_row(r).map_err(|_| Halt::Failed("task record is malformed".into())))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|t| context_id.is_empty() || t.context_id == context_id)
        .filter(|t| wanted.is_none_or(|w| t.state == w))
        .filter(|t| since.is_none_or(|s| i128::from(t.updated_at) * 1_000_000_000 >= s))
        .collect();
    rows.sort_by(|a, b| {
        (b.updated_at, b.task_id.as_str()).cmp(&(a.updated_at, a.task_id.as_str()))
    });
    let cursor = token
        .split_once(':')
        .and_then(|(ts, id)| ts.parse::<u64>().ok().map(|ts| (ts, id)));
    let start = cursor.map_or(0, |cursor| {
        rows.partition_point(|t| (t.updated_at, t.task_id.as_str()) >= cursor)
    });
    let page = &rows[start..rows.len().min(start.saturating_add(page_size))];
    let next = if start + page.len() < rows.len() {
        page.last().map(cursor_of).unwrap_or_default()
    } else {
        String::new()
    };
    Ok(ok(
        rpc_id,
        json!({
            "tasks": page.iter().map(|t| task_json(t)).collect::<Vec<_>>(),
            "nextPageToken": next,
            "pageSize": i32::try_from(page_size).unwrap_or(i32::MAX),
            "totalSize": i32::try_from(rows.len()).unwrap_or(i32::MAX),
        }),
    ))
}

/// ONE registered push config: the push_config host record's value. A read verb answers with
/// `id` and `url` only; the `authentication` credential is a [`Cred`] the SDK's record encoder
/// alone writes ([`crate::push::record_value`]), never a member of any answer, and its `Debug` is
/// redacted.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct PushConfig {
    /// The caller's id for it.
    pub id: String,
    /// The callback URL, exactly as registered and as it passed the floor.
    pub url: String,
    /// The credential the caller asked busbar to present at the webhook, if any. A record written
    /// before the field existed reads as `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentication: Option<DeliveryAuth>,
    /// The A2A version the config was registered under (`0.3` or `1.0`): the shape its
    /// notifications take. A record written before the field existed reads empty, as `1.0`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub version: String,
}

impl<'de> Deserialize<'de> for PushConfig {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Wire {
            id: String,
            #[serde(deserialize_with = "crate::record::callback_field")]
            url: crate::proto::custody::Guard<String>,
            #[serde(default)]
            authentication: Option<DeliveryAuth>,
            #[serde(default)]
            version: String,
        }
        let mut wire = Wire::deserialize(de)?;
        Ok(Self {
            id: wire.id,
            url: wire.url.take(),
            authentication: wire.authentication,
            version: wire.version,
        })
    }
}

impl Drop for PushConfig {
    fn drop(&mut self) {
        crate::request_json::wipe_string(&mut self.url);
    }
}
impl std::fmt::Debug for PushConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PushConfig")
            .field("id", &self.id)
            .field("url", &"<redacted>")
            .field("authentication", &"<redacted>")
            .field("version", &self.version)
            .finish()
    }
}

/// The config as `dialect` spells it; never with `authentication`.
#[must_use]
pub fn config_json(dialect: Dialect, task_id: &str, cfg: &PushConfig) -> Value {
    match dialect {
        Dialect::V10 => json!({ "taskId": task_id, "id": cfg.id, "url": cfg.url }),
        Dialect::V03 => json!({
            "taskId": task_id,
            "pushNotificationConfig": { "id": cfg.id, "url": cfg.url },
        }),
    }
}

/// The config members of a request, nested (v0.3) or flat (v1.0).
#[must_use]
pub fn config_params(params: &Value) -> &Value {
    params.get("pushNotificationConfig").unwrap_or(params)
}

/// THE CONFIG ID a get/delete names: `id` on v1.0, `pushNotificationConfigId` on v0.3 (where `id`
/// is the TASK); empty when absent.
#[must_use]
pub fn config_id_wanted(dialect: Dialect, params: &Value) -> &str {
    config_id_value(dialect, params)
        .and_then(Value::as_str)
        .unwrap_or_default()
}

fn config_id_value(dialect: Dialect, params: &Value) -> Option<&Value> {
    match dialect {
        Dialect::V10 => config_params(params).get("id"),
        Dialect::V03 => params.get("pushNotificationConfigId"),
    }
}

/// THE CREDENTIAL a config names, out of `{scheme, credentials}` or `{schemes: [..], credentials}`;
/// `Ok(None)` for none.
///
/// # Errors
/// A credential busbar cannot present, in words that never quote it back.
pub fn delivery_auth(cfg: &Value) -> Result<Option<DeliveryAuth>, String> {
    let Some(auth) = cfg.get("authentication").filter(|v| !v.is_null()) else {
        return Ok(None);
    };
    let scheme = auth
        .get("scheme")
        .and_then(Value::as_str)
        .or_else(|| {
            auth.get("schemes")
                .and_then(Value::as_array)
                .and_then(|a| a.first())
                .and_then(Value::as_str)
        })
        .unwrap_or_default()
        .to_string();
    if scheme.is_empty() {
        return Err(
            "a push notification config's `authentication` must name a `scheme` (an HTTP \
             authentication scheme such as `Bearer`), because the scheme is what busbar puts in \
             front of the credential on the `Authorization` header it sends to your receiver"
                .to_string(),
        );
    }
    if !scheme
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
    {
        return Err(format!(
            "the push notification config's authentication scheme `{scheme}` is not an HTTP \
             authentication scheme name: it must be a single token of printable ASCII"
        ));
    }
    let credentials = match auth.get("credentials") {
        None | Some(Value::Null) => "",
        Some(Value::String(c)) => c.as_str(),
        Some(_) => {
            return Err(
                "a push notification config's authentication `credentials` must be a string \
                 (the value busbar puts after the scheme on the `Authorization` header)"
                    .to_string(),
            )
        }
    };
    if credentials
        .bytes()
        .any(|b| !b.is_ascii_graphic() && b != b' ')
    {
        return Err(
            "the push notification config's authentication `credentials` contain a byte that \
             cannot appear in an HTTP header field value"
                .to_string(),
        );
    }
    Ok(Some(DeliveryAuth {
        scheme,

        credentials: Cred::captured(Zeroizing::new(credentials.as_bytes().to_vec())),
    }))
}

/// The callback floor: the push-notification guard, its words rendered here and its decision the
/// host's destination judge, asked at registration as push delivery asks it on every attempt.
///
/// # Errors
/// [`Halt`] from the judge; `Ok(Err(words))` for a refused callback, in the guard's words.
pub fn judge_callback(reach: &mut dyn Reach, url: &str) -> Result<Result<(), String>, Halt> {
    use busbar_contract::abi::host::service::{
        DEST_ALLOWED, DEST_INTERNAL, DEST_METADATA, DEST_NO_ADDRESSES, DEST_NO_HOST,
        DEST_OBFUSCATED, DEST_PLAINTEXT, DEST_SCHEME, DEST_UNRESOLVABLE,
    };
    use busbar_contract::net::{parse_url, UrlRefusal};

    let malformed = || {
        Ok(Err(format!(
            "push callback URL is malformed: `{}`",
            crate::a2a::config::without_userinfo(url)
        )))
    };
    let Some((scheme, _)) = url.split_once("://") else {
        return malformed();
    };
    if scheme.is_empty()
        || !scheme
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
    {
        return malformed();
    }
    let parts = match parse_url(url) {
        Ok(p) if !p.userinfo => p,
        Err(UrlRefusal::NoHost) => return Ok(Err("push callback URL has no host".into())),
        _ => return malformed(),
    };
    let host = parts.host.to_ascii_lowercase();
    Ok(match reach.judge(url)? {
        DEST_ALLOWED => Ok(()),
        DEST_SCHEME | DEST_PLAINTEXT => Err(format!(
            "push callback scheme `{}` is refused; a callback carries task metadata off-box \
             and must be https",
            parts.scheme
        )),
        DEST_NO_HOST => return malformed(),
        DEST_OBFUSCATED => Err(format!(
            "push callback host `{host}` is an alternate IPv4 encoding, which resolves to an \
             address a canonical literal check would not see"
        )),
        DEST_UNRESOLVABLE | DEST_NO_ADDRESSES => Err(format!(
            "push callback host `{host}` resolved to no addresses; nothing was checked, so \
             nothing is allowed"
        )),
        DEST_INTERNAL | DEST_METADATA => Err(format!(
            "push callback resolves to the INTERNAL address {host}; delivering there would lend \
             busbar's network position to the caller"
        )),
        _ => Err(
            "the destination judge refused the push callback with an unrecognized verdict".into(),
        ),
    })
}

/// THE TASK a push-config request names, through the same scoped read every verb uses: its
/// FIRST task member present, and that one only.
pub(crate) fn addressed(
    rec: &mut dyn Records,
    dialect: Dialect,
    params: &Value,
    caller: &str,
    now: u64,
) -> Result<Option<Task>, Halt> {
    let Some(id) = addressed_id(dialect, params) else {
        return Ok(None);
    };
    tasks::get(rec, caller, id, now)?
        .map(|held| {
            Task::from_row(&held.row).map_err(|_| Halt::Failed("task record is malformed".into()))
        })
        .transpose()
}

/// The first supplied task member, preserving dialect precedence and empty-string semantics.
fn addressed_id(dialect: Dialect, params: &Value) -> Option<&str> {
    let members: &[&str] = match dialect {
        Dialect::V10 => &["taskId", "task_id"],
        Dialect::V03 => &["taskId", "id"],
    };
    members
        .iter()
        .find_map(|member| params.get(*member))
        .and_then(Value::as_str)
}

/// The config held for `caller`'s task `task_id`, if any.
pub(crate) fn held_config(
    rec: &mut dyn Records,
    caller: &str,
    task_id: &str,
) -> Result<Option<PushConfig>, Halt> {
    rec.get(KIND_PUSH_CONFIG, &task_key(caller, task_id))?
        .map(|b| decode_config(&Zeroizing::new(b)))
        .transpose()
}

fn decode_config(bytes: &[u8]) -> Result<PushConfig, Halt> {
    crate::request_json::from_slice(bytes)
        .map_err(|_| Halt::Failed("push config record is malformed".into()))
}

/// The refusal for a push config's non-null `token`, which no delivery presents. Shared with
/// inline callbacks so the two entry points make the same promise.
pub const TOKEN_UNCARRIED: &str =
    "busbar does not carry a push notification config `token`: there is no header or body \
     member the delivery puts it in, so storing it would promise the receiver a value it \
     never sees. Use `authentication`, which busbar presents on the `Authorization` header, \
     or register the secret in the callback URL your receiver checks.";

/// `CreateTaskPushNotificationConfig` / `tasks/pushNotificationConfig/set`.
fn create_push_config(
    reach: &mut dyn Reach,
    dialect: Dialect,
    params: &Value,
    rpc_id: &Value,
    caller: &str,
    now: u64,
    _out: &mut Vec<Write>,
) -> Result<LocalAnswer, Halt> {
    let Some(task) = addressed(reach, dialect, params, caller, now)? else {
        return Ok(err(rpc_id, TASK_NOT_FOUND, NO_SUCH_TASK));
    };
    let cfg = config_params(params);
    if cfg
        .get("token")
        .is_some_and(|value| !value.is_null() && value.as_str() != Some(""))
    {
        return Ok(err(rpc_id, UNSUPPORTED_OPERATION, TOKEN_UNCARRIED));
    }
    let authentication = match delivery_auth(cfg) {
        Ok(auth) => auth,
        Err(message) => return Ok(err(rpc_id, INVALID_PARAMS, message)),
    };
    let Some(url) = cfg.get("url").and_then(Value::as_str) else {
        return Ok(err(
            rpc_id,
            INVALID_PARAMS,
            "a push notification config must name the `url` busbar is to call",
        ));
    };
    let id = cfg
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .unwrap_or(&task.task_id)
        .to_string();
    let stored = PushConfig {
        id,
        url: url.to_string(),
        authentication,
        version: dialect.version().to_string(),
    };
    let value = crate::relay::RawBytes::from(
        crate::push::record_value(&stored).map_err(|e| Halt::Failed(e.to_string()))?,
    );
    let at = tasks::Stamp {
        caller,
        request_id: &task.task_id,
        now,
    };
    if let Err(message) = judge_callback(reach, url)? {
        return Ok(err(rpc_id, INVALID_PARAMS, message));
    }
    for _ in tasks::attempts() {
        let expected = reach
            .get(KIND_PUSH_CONFIG, &task_key(caller, &task.task_id))?
            .map(crate::relay::RawBytes::from);
        let current = expected.as_deref().map(decode_config).transpose()?;
        if current.is_some_and(|config| config.id != stored.id) {
            return Ok(err(
                rpc_id,
                UNSUPPORTED_OPERATION,
                "this task already has a push notification config and busbar holds exactly one \
                 per task: its durable task row carries one callback and its delivery is one \
                 request. Delete the existing config before registering another.",
            ));
        }
        if tasks::write_config(
            reach,
            &at,
            &task.task_id,
            expected.map(crate::relay::RawBytes::into_vec),
            value.clone().into_vec(),
        )? {
            return Ok(ok(rpc_id, config_json(dialect, &task.task_id, &stored)));
        }
    }
    Err(Halt::Failed(
        "push config kept changing under this write".into(),
    ))
}

/// `GetTaskPushNotificationConfig` / `tasks/pushNotificationConfig/get`.
fn get_push_config(
    rec: &mut dyn Records,
    dialect: Dialect,
    params: &Value,
    rpc_id: &Value,
    caller: &str,
    now: u64,
) -> Result<LocalAnswer, Halt> {
    let Some(task) = addressed(rec, dialect, params, caller, now)? else {
        return Ok(err(rpc_id, TASK_NOT_FOUND, NO_SUCH_TASK));
    };
    let supplied_id = config_id_value(dialect, params);
    if supplied_id.is_some_and(|value| !value.is_null() && !value.is_string()) {
        return Ok(err(
            rpc_id,
            INVALID_PARAMS,
            "a push notification config id must be a string when supplied",
        ));
    }
    let wanted = config_id_wanted(dialect, params);

    let any = dialect == Dialect::V03
        && params
            .get("pushNotificationConfigId")
            .is_none_or(Value::is_null);
    Ok(
        match held_config(rec, caller, &task.task_id)?.filter(|c| any || c.id == wanted) {
            Some(cfg) => ok(rpc_id, config_json(dialect, &task.task_id, &cfg)),
            None => err(
                rpc_id,
                TASK_NOT_FOUND,
                "no push notification config with that id is registered for this task",
            ),
        },
    )
}

/// `ListTaskPushNotificationConfigs` / `tasks/pushNotificationConfig/list`.
fn list_push_configs(
    rec: &mut dyn Records,
    dialect: Dialect,
    params: &Value,
    rpc_id: &Value,
    caller: &str,
    now: u64,
) -> Result<LocalAnswer, Halt> {
    let Some(task) = addressed(rec, dialect, params, caller, now)? else {
        return Ok(err(rpc_id, TASK_NOT_FOUND, NO_SUCH_TASK));
    };
    let held: Vec<Value> = held_config(rec, caller, &task.task_id)?
        .map(|c| vec![config_json(dialect, &task.task_id, &c)])
        .unwrap_or_default();
    Ok(match dialect {
        Dialect::V10 => ok(rpc_id, json!({ "configs": held, "nextPageToken": "" })),
        Dialect::V03 => ok(rpc_id, Value::Array(held)),
    })
}

/// `DeleteTaskPushNotificationConfig` / `tasks/pushNotificationConfig/delete`. IDEMPOTENT: a
/// config that is not there is no error; a different held id is not found, and a matching id
/// goes as a tombstone.
fn delete_push_config(
    rec: &mut dyn Records,
    dialect: Dialect,
    params: &Value,
    rpc_id: &Value,
    caller: &str,
    now: u64,
    _out: &mut Vec<Write>,
) -> Result<LocalAnswer, Halt> {
    let Some(task) = addressed(rec, dialect, params, caller, now)? else {
        return Ok(err(rpc_id, TASK_NOT_FOUND, NO_SUCH_TASK));
    };
    let wanted = config_id_wanted(dialect, params);
    let at = tasks::Stamp {
        caller,
        request_id: &task.task_id,
        now,
    };
    for _ in tasks::attempts() {
        let expected = rec
            .get(KIND_PUSH_CONFIG, &task_key(caller, &task.task_id))?
            .map(crate::relay::RawBytes::from);
        let current = expected.as_deref().map(decode_config).transpose()?;
        if current.as_ref().is_some_and(|config| config.id != wanted) {
            return Ok(err(
                rpc_id,
                TASK_NOT_FOUND,
                "no push notification config with that id is registered for this task",
            ));
        }
        if current.is_none()
            || tasks::write_config(
                rec,
                &at,
                &task.task_id,
                expected.map(crate::relay::RawBytes::into_vec),
                Vec::new(),
            )?
        {
            return Ok(match dialect {
                Dialect::V03 => ok(rpc_id, Value::Null),
                Dialect::V10 => ok(rpc_id, json!({})),
            });
        }
    }
    Err(Halt::Failed(
        "push config kept changing under this deletion".into(),
    ))
}

/// The refusal a subscribe earns from busbar's own record, or `None` when the backend answers.
fn subscribe_refusal(
    rec: &mut dyn Records,
    params: &Value,
    rpc_id: &Value,
    caller: &str,
    now: u64,
) -> Result<Option<LocalAnswer>, Halt> {
    let Some(named) = ["id", "taskId", "task_id"]
        .iter()
        .find_map(|m| params.get(*m))
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
    else {
        return Ok(Some(err(
            rpc_id,
            INVALID_PARAMS,
            "a subscription must name a task id",
        )));
    };
    Ok(match tasks::get(rec, caller, named, now)? {
        None => Some(err(rpc_id, TASK_NOT_FOUND, NO_SUCH_TASK)),
        Some(held) => match Task::from_row(&held.row) {
            Ok(task) if task.state.is_terminal() => Some(err(
                rpc_id,
                UNSUPPORTED_OPERATION,
                "this task has reached a terminal state, so there are no further events to \
                 subscribe to",
            )),
            Err(error) => {
                return Err(Halt::Failed(format!(
                    "the held task could not be read: {error}"
                )))
            }
            Ok(_) => None,
        },
    })
}

#[cfg(test)]
#[path = "tests/local.rs"]
mod tests;
