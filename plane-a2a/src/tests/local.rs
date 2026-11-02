// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The verbs the plane answers itself, over the test's host records: the engine's bytes, and a

use busbar_contract::abi::host::service::{
    DEST_ALLOWED, DEST_INTERNAL, DEST_NO_HOST, DEST_OBFUSCATED, DEST_PLAINTEXT, DEST_SCHEME,
    DEST_UNRESOLVABLE,
};

use super::*;

#[path = "g2_local_protocol.rs"]
mod g2_local_protocol;

#[path = "local_residual_cases.rs"]
mod local_residual_cases;

include!(concat!(env!("OUT_DIR"), "/method_inventory.rs"));
use crate::tasks::tests::{step, submitted, Book, ALICE, BOB};

/// The host records, the destination judge's one verdict, and every destination it was asked.
struct Desk {
    book: Book,
    verdict: u64,
    judged: Vec<String>,
}

impl Records for Desk {
    fn get(&mut self, kind: &str, key: &str) -> Result<Option<Vec<u8>>, Halt> {
        self.book.get(kind, key)
    }
    fn list(&mut self, kind: &str, prefix: &str) -> Result<Vec<(String, Vec<u8>)>, Halt> {
        self.book.list(kind, prefix)
    }
    fn claim(&mut self, kind: &str, key: &str, ttl_ms: u64) -> Result<bool, Halt> {
        self.book.claim(kind, key, ttl_ms)
    }
    fn observe_chain_life(&mut self, kind: &str, scope: &str) -> Result<Option<Vec<u8>>, Halt> {
        self.book.observe_chain_life(kind, scope)
    }
    fn publish(
        &mut self,
        predicates: &[tasks::Predicate],
        chains: &[tasks::ChainLife],
        writes: &[Write],
    ) -> Result<bool, Halt> {
        self.book.publish(predicates, chains, writes)
    }
}

impl Reach for Desk {
    fn judge(&mut self, dest: &str) -> Result<u64, Halt> {
        self.judged.push(dest.to_string());
        Ok(self.verdict)
    }
}

/// Alice holds `t1` and `t2`, Bob `t3`.
fn desk() -> Desk {
    let mut book = Book::default();
    submitted(&mut book, ALICE, "t1", 100);
    submitted(&mut book, ALICE, "t2", 200);
    submitted(&mut book, BOB, "t3", 100);
    Desk {
        book,
        verdict: DEST_ALLOWED,
        judged: Vec::new(),
    }
}

/// Call `method` with `params` as `caller` and apply its writes: the status and the parsed body.
fn call(desk: &mut Desk, method: &str, params: Value, caller: &str) -> (u32, Value) {
    let verb = verb_of(method).expect("a local verb");
    let envelope = json!({ "jsonrpc": "2.0", "id": 7, "method": method, "params": params });
    let mut out = Vec::new();
    let answer = answer_local(desk, verb, &envelope, caller, 300, &mut out)
        .unwrap()
        .expect("answered here");
    desk.book.apply(&out);
    (answer.status, serde_json::from_slice(&answer.body).unwrap())
}

/// The error a body carries: its code and its message.
fn error_of(body: &Value) -> (i64, String) {
    (
        body["error"]["code"].as_i64().unwrap(),
        body["error"]["message"].as_str().unwrap().to_string(),
    )
}

/// `ListTasks` answers the caller's own rows, newest first, one page at a time, with the engine's

#[test]
fn list_tasks_answers_the_callers_own_rows_a_page_at_a_time() {
    let mut desk = desk();
    let (status, body) = call(&mut desk, "ListTasks", json!({ "pageSize": 1 }), ALICE);
    assert_eq!(status, 200);
    assert_eq!(body["id"], 7);
    let result = &body["result"];
    assert_eq!(
        result["tasks"],
        json!([{ "id": "t2", "contextId": "ctx-1", "status": { "state": "TASK_STATE_SUBMITTED" } }])
    );
    assert_eq!(
        (result["pageSize"].clone(), result["totalSize"].clone()),
        (json!(1), json!(2))
    );
    assert_eq!(result["nextPageToken"], "200:t2");
    let (_, body) = call(
        &mut desk,
        "tasks/list",
        json!({ "page_token": "200:t2" }),
        ALICE,
    );
    assert_eq!(body["result"]["tasks"][0]["id"], "t1");
    assert_eq!(
        body["result"]["nextPageToken"], "",
        "present, and empty on the last page"
    );
    let (_, body) = call(
        &mut desk,
        "ListTasks",
        json!({ "status": "completed" }),
        ALICE,
    );
    assert_eq!(body["result"]["totalSize"], 0);
}

/// A PAGE HOLDS AT MOST 100 TASKS, the protocol's maximum (`ListTasksRequest.page_size`, a2a.proto:

#[test]
fn list_tasks_pages_at_most_the_protocols_hundred() {
    let mut desk = desk();
    for n in 0..120u64 {
        submitted(&mut desk.book, ALICE, &format!("bulk-{n}"), 1_000 + n);
    }
    let (status, body) = call(&mut desk, "ListTasks", json!({ "pageSize": 150 }), ALICE);
    assert_eq!(status, 200);
    assert_eq!(body["result"]["tasks"].as_array().map(Vec::len), Some(100));
    assert_eq!(body["result"]["pageSize"], 100);
    assert_ne!(body["result"]["nextPageToken"], "");
}

/// A config is created, read, listed and deleted as a record of its task, in each dialect's shape,

#[test]
fn a_push_config_lives_as_a_record_of_its_task() {
    let mut desk = desk();
    let cfg = json!({ "taskId": "t1", "id": "c1", "url": "https://hooks.example/cb",
                      "authentication": { "scheme": "Bearer", "credentials": "s3cret" } });
    let (status, body) = call(&mut desk, "CreateTaskPushNotificationConfig", cfg, ALICE);
    assert_eq!(status, 200);
    assert_eq!(
        body["result"],
        json!({ "taskId": "t1", "id": "c1", "url": "https://hooks.example/cb" })
    );
    assert!(!body.to_string().contains("s3cret"));
    assert!(desk
        .book
        .value(KIND_PUSH_CONFIG, &task_key(ALICE, "t1"))
        .is_some());

    let (_, body) = call(
        &mut desk,
        "tasks/pushNotificationConfig/get",
        json!({ "id": "t1", "pushNotificationConfigId": "c1" }),
        ALICE,
    );
    assert_eq!(
        body["result"],
        json!({ "taskId": "t1", "pushNotificationConfig": { "id": "c1", "url": "https://hooks.example/cb" } })
    );
    let (_, body) = call(
        &mut desk,
        "tasks/pushNotificationConfig/list",
        json!({ "id": "t1" }),
        ALICE,
    );
    assert_eq!(
        body["result"],
        json!([{ "taskId": "t1", "pushNotificationConfig": { "id": "c1", "url": "https://hooks.example/cb" } }])
    );
    assert!(!body.to_string().contains("s3cret"));
    let (_, body) = call(
        &mut desk,
        "ListTaskPushNotificationConfigs",
        json!({ "taskId": "t1" }),
        ALICE,
    );
    assert_eq!(body["result"]["nextPageToken"], "");
    assert_eq!(body["result"]["configs"].as_array().map(Vec::len), Some(1));

    let second = json!({ "taskId": "t1", "id": "c2", "url": "https://hooks.example/cb" });
    let (status, body) = call(&mut desk, "CreateTaskPushNotificationConfig", second, ALICE);
    assert_eq!(
        (status, error_of(&body).0),
        (400, -32004),
        "one config per task"
    );

    let (_, body) = call(
        &mut desk,
        "DeleteTaskPushNotificationConfig",
        json!({ "taskId": "t1", "id": "c1" }),
        ALICE,
    );
    assert_eq!(body["result"], json!({}));
    assert!(
        desk.book
            .value(KIND_PUSH_CONFIG, &task_key(ALICE, "t1"))
            .is_none(),
        "a tombstone"
    );
    let (status, body) = call(
        &mut desk,
        "GetTaskPushNotificationConfig",
        json!({ "taskId": "t1", "id": "c1" }),
        ALICE,
    );
    assert_eq!(status, 404);
    assert_eq!(
        error_of(&body).1,
        "no push notification config with that id is registered for this task"
    );
    let (_, body) = call(
        &mut desk,
        "tasks/pushNotificationConfig/delete",
        json!({ "id": "t1", "pushNotificationConfigId": "c1" }),
        ALICE,
    );
    assert_eq!(body["result"], Value::Null, "idempotent, v0.3's null");
}

/// The credential rides the stored record (the SDK's record encoder) and appears in no answer.
#[test]
fn the_stored_credential_rides_the_record_and_never_an_answer() {
    let mut desk = desk();
    let cfg = json!({ "taskId": "t1", "id": "c1", "url": "https://hooks.example/cb",
                      "authentication": { "scheme": "Bearer", "credentials": "s3cret" } });
    let (_, created) = call(&mut desk, "CreateTaskPushNotificationConfig", cfg, ALICE);
    let bytes = desk
        .book
        .value(KIND_PUSH_CONFIG, &task_key(ALICE, "t1"))
        .expect("the record");
    let held: PushConfig = serde_json::from_slice(bytes).unwrap();
    assert_eq!(
        held.authentication,
        Some(DeliveryAuth {
            scheme: "Bearer".into(),
            credentials: busbar_contract::abi::sdk::test_support::chip::cred("s3cret"),
        })
    );
    assert!(!format!("{held:?}").contains("s3cret"));
    let (_, got) = call(
        &mut desk,
        "GetTaskPushNotificationConfig",
        json!({ "taskId": "t1", "id": "c1" }),
        ALICE,
    );
    let (_, listed) = call(
        &mut desk,
        "ListTaskPushNotificationConfigs",
        json!({ "taskId": "t1" }),
        ALICE,
    );
    for body in [created, got, listed] {
        assert!(!body.to_string().contains("s3cret"));
    }
}

/// A record written before the field existed still reads, and a config without a credential

#[test]
fn a_record_without_the_credential_field_reads_as_none() {
    let old: PushConfig =
        serde_json::from_str(r#"{"id":"c1","url":"https://hooks.example/cb"}"#).unwrap();
    assert_eq!(old.authentication, None);
    assert!(!serde_json::to_string(&old)
        .unwrap()
        .contains("authentication"));
    let kept = PushConfig {
        authentication: Some(DeliveryAuth {
            scheme: "Basic".into(),
            credentials: busbar_contract::abi::sdk::test_support::chip::cred("abc"),
        }),
        ..old
    };
    let again: PushConfig =
        serde_json::from_slice(&crate::push::record_value(&kept).unwrap()).unwrap();
    assert_eq!(again, kept);
}

/// Another caller's task is not found, with the engine's ErrorInfo, at 404.
#[test]
fn another_callers_task_is_not_found() {
    let mut desk = desk();
    let (status, body) = call(
        &mut desk,
        "GetTaskPushNotificationConfig",
        json!({ "taskId": "t3", "id": "" }),
        ALICE,
    );
    assert_eq!(status, 404);
    assert_eq!(
        body,
        json!({ "jsonrpc": "2.0", "id": 7, "error": { "code": -32001, "message": NO_SUCH_TASK,
            "data": [{ "@type": crate::ERROR_INFO_TYPE, "domain": crate::ERROR_INFO_DOMAIN, "reason": "TASK_NOT_FOUND" }] } })
    );
}

/// Refused callback configurations retain their error status/code and create no config record.

#[test]
fn refused_callback_configurations_are_not_persisted() {
    let cases: [(Value, u64, i64, &str); 7] = [
        (json!({ "url": "http://hooks.example/" }), DEST_PLAINTEXT, -32602, "push callback scheme `http` is refused; a callback carries task metadata off-box and must be https"),
        (json!({ "url": "https://10.0.0.1/" }), DEST_INTERNAL, -32602, "push callback resolves to the INTERNAL address 10.0.0.1; delivering there would lend busbar's network position to the caller"),
        (json!({ "url": "https://gone.example/" }), DEST_UNRESOLVABLE, -32602, "push callback host `gone.example` resolved to no addresses; nothing was checked, so nothing is allowed"),
        (json!({ "url": "https://inside.example/" }), DEST_INTERNAL, -32602, "push callback resolves to the INTERNAL address inside.example; delivering there would lend busbar's network position to the caller"),
        (json!({ "url": "https://hooks.example/", "token": "t" }), DEST_ALLOWED, -32004, "busbar does not carry a push notification config `token`"),
        (json!({ "url": "https://hooks.example/", "authentication": { "credentials": "x" } }), DEST_ALLOWED, -32602, "a push notification config's `authentication` must name a `scheme`"),
        (json!({ "id": "c" }), DEST_ALLOWED, -32602, "a push notification config must name the `url` busbar is to call"),
    ];
    for (cfg, verdict, code, words) in cases {
        let mut desk = desk();
        desk.verdict = verdict;
        let params = json!({ "id": "t1", "pushNotificationConfig": cfg });
        let (status, body) = call(&mut desk, "tasks/pushNotificationConfig/set", params, ALICE);
        let (got, message) = error_of(&body);
        assert_eq!((status, got), (400, code), "{message}");
        assert!(message.starts_with(words), "{message}");
        assert!(desk
            .book
            .value(KIND_PUSH_CONFIG, &task_key(ALICE, "t1"))
            .is_none());
    }
}

/// A subscribe to a task busbar did not issue to this caller is not found, to one it holds as

#[test]
fn a_subscribe_is_refused_only_where_busbar_knows_better() {
    let mut desk = desk();
    let mut out = Vec::new();
    crate::tasks::transition(
        &mut desk.book,
        &step(ALICE, 250),
        "t2",
        TaskState::Completed,
        &mut out,
    )
    .unwrap();
    desk.book.apply(&out);
    let envelope = |id: &str| json!({ "jsonrpc": "2.0", "id": 1, "method": "SubscribeToTask", "params": { "id": id } });
    let refused = |desk: &mut Desk, id: &str| {
        answer_local(
            desk,
            LocalVerb::Subscribe,
            &envelope(id),
            ALICE,
            300,
            &mut Vec::new(),
        )
        .unwrap()
    };
    assert_eq!(refused(&mut desk, "t3").map(|a| a.status), Some(404));
    assert_eq!(refused(&mut desk, "t2").map(|a| a.status), Some(400));
    assert_eq!(refused(&mut desk, "t1"), None);
}

/// Exactly the task-store verbs are answered here; the submission and read verbs are the

#[test]
fn exactly_these_methods_are_answered_locally() {
    for m in [
        "ListTasks",
        "tasks/list",
        "CreateTaskPushNotificationConfig",
        "tasks/pushNotificationConfig/set",
        "GetTaskPushNotificationConfig",
        "tasks/pushNotificationConfig/get",
        "ListTaskPushNotificationConfigs",
        "tasks/pushNotificationConfig/list",
        "DeleteTaskPushNotificationConfig",
        "tasks/pushNotificationConfig/delete",
        "SubscribeToTask",
        "tasks/resubscribe",
    ] {
        assert!(verb_of(m).is_some(), "`{m}` must be answered locally");
    }
    for m in [
        "SendMessage",
        "message/send",
        "SendStreamingMessage",
        "message/stream",
        "GetTask",
        "tasks/get",
        "CancelTask",
        "tasks/cancel",
        "GetExtendedAgentCard",
    ] {
        assert!(verb_of(m).is_none(), "`{m}` must be relayed");
    }
}

/// Each push verb carries the dialect its spelling names, so its answer takes that dialect's shape.
#[test]
fn the_push_verbs_carry_the_dialect_that_named_them() {
    type Spelled = (&'static str, &'static str, fn(Dialect) -> LocalVerb);
    let pairs: [Spelled; 4] = [
        (
            "CreateTaskPushNotificationConfig",
            "tasks/pushNotificationConfig/set",
            LocalVerb::CreatePushConfig,
        ),
        (
            "GetTaskPushNotificationConfig",
            "tasks/pushNotificationConfig/get",
            LocalVerb::GetPushConfig,
        ),
        (
            "ListTaskPushNotificationConfigs",
            "tasks/pushNotificationConfig/list",
            LocalVerb::ListPushConfigs,
        ),
        (
            "DeleteTaskPushNotificationConfig",
            "tasks/pushNotificationConfig/delete",
            LocalVerb::DeletePushConfig,
        ),
    ];
    for (v10, v03, verb) in pairs {
        assert_eq!(verb_of(v10), Some(verb(Dialect::V10)), "{v10}");
        assert_eq!(verb_of(v03), Some(verb(Dialect::V03)), "{v03}");
    }
}

/// A config cannot be attached to another caller's task: the create is the absent-task refusal,

#[test]
fn a_push_config_cannot_be_attached_to_another_principals_task() {
    let mut desk = desk();
    let cfg = json!({ "task_id": "t1", "id": "cfg-x", "url": "https://hooks.example/cb" });
    let (_, body) = call(&mut desk, "CreateTaskPushNotificationConfig", cfg, BOB);
    assert_eq!(error_of(&body), (-32001, NO_SUCH_TASK.to_string()));
    for caller in [ALICE, BOB] {
        assert!(desk
            .book
            .value(KIND_PUSH_CONFIG, &task_key(caller, "t1"))
            .is_none());
    }
    assert!(
        desk.judged.is_empty(),
        "nothing was judged for a foreign task"
    );
}

/// The list is answered for the owner; for anybody else it is the absent-task refusal, byte for

#[test]
fn list_push_configs_is_answered_for_the_owner_and_is_an_absent_task_for_everybody_else() {
    let mut desk = desk();
    let cfg = json!({ "taskId": "t1", "id": "cfg-l", "url": "https://hooks.example/cb" });
    call(&mut desk, "CreateTaskPushNotificationConfig", cfg, ALICE);
    let list = |desk: &mut Desk, task: &str, caller: &str| {
        call(
            desk,
            "ListTaskPushNotificationConfigs",
            json!({ "taskId": task }),
            caller,
        )
    };
    let (_, mine) = list(&mut desk, "t1", ALICE);
    assert_eq!(mine["result"]["configs"].as_array().map(Vec::len), Some(1));
    let foreign = list(&mut desk, "t1", BOB);
    let absent = list(&mut desk, "never-existed", BOB);
    assert_eq!(foreign, absent);
    assert_eq!(error_of(&foreign.1).0, -32001);
}

/// Another caller's delete cannot disarm the owner's callback: it answers as for an absent task and

#[test]
fn delete_push_config_cannot_disarm_another_principals_callback() {
    let mut desk = desk();
    let cfg = json!({ "taskId": "t1", "id": "cfg-d", "url": "https://hooks.example/cb" });
    call(&mut desk, "CreateTaskPushNotificationConfig", cfg, ALICE);
    let delete = |desk: &mut Desk, task: &str, caller: &str| {
        call(
            desk,
            "DeleteTaskPushNotificationConfig",
            json!({ "taskId": task, "id": "cfg-d" }),
            caller,
        )
    };
    let foreign = delete(&mut desk, "t1", BOB);
    let absent = delete(&mut desk, "never-existed", BOB);
    assert_eq!(foreign, absent);
    assert!(
        desk.book
            .value(KIND_PUSH_CONFIG, &task_key(ALICE, "t1"))
            .is_some(),
        "the owner's callback is still armed"
    );
    let (status, mine) = delete(&mut desk, "t1", ALICE);
    assert_eq!((status, mine["result"].clone()), (200, json!({})));
    assert!(desk
        .book
        .value(KIND_PUSH_CONFIG, &task_key(ALICE, "t1"))
        .is_none());
}

/// A subscribe is relayed for the owner of a live task (no local refusal); for anybody else it is

#[test]
fn subscribe_is_relayed_for_the_owner_and_is_an_absent_task_for_everybody_else() {
    let mut desk = desk();
    let envelope = |id: &str| json!({ "jsonrpc": "2.0", "id": 1, "method": "SubscribeToTask", "params": { "id": id } });
    let mut refusal = |id: &str, caller: &str| {
        answer_local(
            &mut desk,
            LocalVerb::Subscribe,
            &envelope(id),
            caller,
            300,
            &mut Vec::new(),
        )
        .unwrap()
    };
    assert_eq!(refusal("t1", ALICE), None, "the owner's subscribe relays");
    let foreign = refusal("t1", BOB).expect("a foreign id is refused");
    let absent = refusal("never-existed", BOB).expect("an absent id is refused");
    assert_eq!(foreign, absent);
}

/// The v0.3 spelling is answered in the v0.3 shape: the config nested under

#[test]
fn the_v0_3_spelling_is_answered_in_the_v0_3_shape() {
    let mut desk = desk();
    let params = json!({ "taskId": "t1",
                         "pushNotificationConfig": { "id": "cfg-v03", "url": "https://hooks.example/cb" } });
    let (status, body) = call(&mut desk, "tasks/pushNotificationConfig/set", params, ALICE);
    assert_eq!(status, 200, "{body}");
    let created = &body["result"];
    assert_eq!(created["pushNotificationConfig"]["id"], "cfg-v03");
    assert_eq!(
        created["pushNotificationConfig"]["url"],
        "https://hooks.example/cb"
    );
    assert!(
        created.get("url").is_none(),
        "the v1.0 flattening must not leak into a v0.3 answer"
    );
}

/// Every A2A method of the inventory is read the same way under its v1.0 and its v0.3 JSON-RPC

#[test]
fn every_a2a_method_is_read_identically_under_both_of_its_live_json_rpc_names() {
    let doc: Value = serde_json::from_str(METHOD_INVENTORY).expect("the inventory parses");
    let methods = doc["methods"].as_array().expect("a methods array");
    fn how_busbar_reads(method: &str) -> (Option<&'static str>, String, Option<bool>) {
        let verb = verb_of(method).map(|v| match v {
            LocalVerb::ListTasks => "ListTasks",
            LocalVerb::CreatePushConfig(_) => "CreatePushConfig",
            LocalVerb::GetPushConfig(_) => "GetPushConfig",
            LocalVerb::ListPushConfigs(_) => "ListPushConfigs",
            LocalVerb::DeletePushConfig(_) => "DeletePushConfig",
            LocalVerb::Subscribe => "Subscribe",
        });
        let class = crate::ops::relay_class(method).as_str().to_string();
        let streams = crate::ops::row_for(method).map(|r| r.multi_frame);
        (verb, class, streams)
    }
    for m in methods {
        if m["protocol"] != "a2a" || m["kind"] != "rpc" {
            continue;
        }
        let pascal = m["wire_names"]["jsonrpc_1_0"]
            .as_str()
            .expect("an RPC fixture has its v1.0 request method");
        let slash = m["wire_names"]["jsonrpc_0_3"]
            .as_str()
            .expect("an RPC fixture has its v0.3 request method");
        assert_eq!(
            how_busbar_reads(pascal),
            how_busbar_reads(slash),
            "`{pascal}` and `{slash}` are read differently by this plane"
        );
    }
}

/// A v0.3 set then a v0.3 delete naming the config by `pushNotificationConfigId` (the task by `id`)

#[test]
fn v03_delete_reads_pushnotificationconfigid_and_actually_clears() {
    let mut desk = desk();
    let set = json!({ "id": "t1",
                      "pushNotificationConfig": { "id": "cfg-v03", "url": "https://hooks.example/cb" } });
    let (_, created) = call(&mut desk, "tasks/pushNotificationConfig/set", set, ALICE);
    assert_eq!(
        created["result"]["pushNotificationConfig"]["id"], "cfg-v03",
        "{created}"
    );
    assert!(desk
        .book
        .value(KIND_PUSH_CONFIG, &task_key(ALICE, "t1"))
        .is_some());
    let (status, deleted) = call(
        &mut desk,
        "tasks/pushNotificationConfig/delete",
        json!({ "id": "t1", "pushNotificationConfigId": "cfg-v03" }),
        ALICE,
    );
    assert_eq!(status, 200);
    assert!(deleted.get("error").is_none(), "{deleted}");
    assert!(
        desk.book
            .value(KIND_PUSH_CONFIG, &task_key(ALICE, "t1"))
            .is_none(),
        "the record is ACTUALLY cleared"
    );
}

/// The host judges callback destinations, and its refusal prevents the callback.

#[test]
fn an_internal_callback_is_refused_on_the_hosts_verdict_and_the_host_is_asked() {
    let url = "https://10.0.0.1/cb";
    let mut desk = desk();
    desk.verdict = DEST_INTERNAL;
    let cfg = json!({ "taskId": "t1", "id": "c1", "url": url });
    let (status, body) = call(
        &mut desk,
        "CreateTaskPushNotificationConfig",
        cfg.clone(),
        ALICE,
    );
    assert_eq!(status, 400);
    assert_eq!(
        error_of(&body),
        (
            -32602,
            "push callback resolves to the INTERNAL address 10.0.0.1; delivering there would lend \
             busbar's network position to the caller"
                .to_string()
        )
    );
    assert_eq!(desk.judged, vec![url.to_string()], "the host decided it");

    let mut admitted = self::desk();
    let (status, body) = call(
        &mut admitted,
        "CreateTaskPushNotificationConfig",
        cfg,
        ALICE,
    );
    assert_eq!(
        status, 200,
        "no check of the plane's own refuses it: {body}"
    );
    assert_eq!(admitted.judged, vec![url.to_string()]);
}

/// The callback consumes the host's DEST_OBFUSCATED verdict. Detection of the

#[test]
fn the_hosts_obfuscated_address_verdict_is_refused() {
    for host in [
        "2130706433",
        "0x7f000001",
        "017700000001",
        "127.1",
        "0xa9.0xfe.0xa9.0xfe",
    ] {
        let url = format!("https://{host}/cb");
        let mut desk = desk();
        desk.verdict = DEST_OBFUSCATED;
        let cfg = json!({ "taskId": "t1", "id": "c1", "url": url });
        let (_, body) = call(&mut desk, "CreateTaskPushNotificationConfig", cfg, ALICE);
        assert_eq!(
            error_of(&body),
            (
                -32602,
                format!(
                    "push callback host `{host}` is an alternate IPv4 encoding, which resolves to \
                     an address a canonical literal check would not see"
                )
            ),
            "`{host}`"
        );
        assert_eq!(desk.judged, vec![url.clone()]);
    }
}

/// A URL whose authority names a user is malformed, refused rather than normalised, before the

#[test]
fn a_url_with_userinfo_is_refused_rather_than_normalised() {
    for (url, shown) in [
        (
            "https://169.254.169.254@caller.example/cb",
            "https://***@caller.example/cb",
        ),
        (
            "https://alice:s3cret@caller.example/cb",
            "https://***@caller.example/cb",
        ),
    ] {
        let mut desk = desk();
        let cfg = json!({ "taskId": "t1", "id": "c1", "url": url });
        let (_, body) = call(&mut desk, "CreateTaskPushNotificationConfig", cfg, ALICE);
        assert_eq!(
            error_of(&body),
            (-32602, format!("push callback URL is malformed: `{shown}`"))
        );
        assert!(!body.to_string().contains("s3cret"), "{body}");
        assert!(desk.judged.is_empty());
    }
}

/// A v1.0 PUSH-CONFIG VERB READS ITS TASK FROM `taskId` ALONE: `id` is the config's id, so a

#[test]
fn a_v10_push_config_verb_never_reads_its_config_id_as_the_task() {
    let mut desk = desk();
    let cfg = json!({ "taskId": "t1", "id": "c1", "url": "https://hooks.example/cb" });
    call(&mut desk, "CreateTaskPushNotificationConfig", cfg, ALICE);

    let (status, body) = call(
        &mut desk,
        "CreateTaskPushNotificationConfig",
        json!({ "taskId": "nope", "id": "t2", "url": "https://hooks.example/cb" }),
        ALICE,
    );
    assert_eq!((status, error_of(&body).0), (404, -32001));
    assert!(desk
        .book
        .value(KIND_PUSH_CONFIG, &task_key(ALICE, "t2"))
        .is_none());
    for method in [
        "GetTaskPushNotificationConfig",
        "DeleteTaskPushNotificationConfig",
    ] {
        let (_, body) = call(
            &mut desk,
            method,
            json!({ "taskId": "nope", "id": "t1" }),
            ALICE,
        );
        assert_eq!(error_of(&body).0, -32001, "{method}");
    }
    let (status, body) = call(
        &mut desk,
        "GetTaskPushNotificationConfig",
        json!({ "id": "t1" }),
        ALICE,
    );
    assert_eq!(
        (status, error_of(&body).0),
        (400, -32602),
        "v1.0 `id` alone is a malformed task reference, not a lookup of the config id"
    );
    let (_, body) = call(
        &mut desk,
        "tasks/pushNotificationConfig/get",
        json!({ "id": "t1", "pushNotificationConfigId": "c1" }),
        ALICE,
    );
    assert_eq!(body["result"]["pushNotificationConfig"]["id"], "c1");
}

/// A string that is not a URL is refused, and a scheme the host does not admit is refused in the

#[test]
fn malformed_urls_are_refused() {
    let words = |shown: &str| format!("push callback URL is malformed: `{shown}`");
    for (url, verdict, said) in [
        ("not-a-url", DEST_ALLOWED, words("<malformed URL omitted>")),
        (
            "https:/caller.example",
            DEST_ALLOWED,
            words("https:/caller.example"),
        ),
        (
            "https://",
            DEST_ALLOWED,
            "push callback URL has no host".to_string(),
        ),
        ("://x", DEST_ALLOWED, words("<malformed URL omitted>")),
        (
            "https://caller.example:99999/",
            DEST_NO_HOST,
            words("<malformed URL omitted>"),
        ),
        (
            "ftp://caller.example/",
            DEST_SCHEME,
            "push callback scheme `ftp` is refused; a callback carries task metadata off-box and \
             must be https"
                .to_string(),
        ),
    ] {
        let mut desk = desk();
        desk.verdict = verdict;
        let cfg = json!({ "taskId": "t1", "id": "c1", "url": url });
        let (status, body) = call(&mut desk, "CreateTaskPushNotificationConfig", cfg, ALICE);
        assert_eq!((status, error_of(&body)), (400, (-32602, said)), "`{url}`");
        assert!(desk
            .book
            .value(KIND_PUSH_CONFIG, &task_key(ALICE, "t1"))
            .is_none());
    }
}

/// THE ENGINE'S ANSWER SHOULD THE STORE REFUSE A PUSH-CONFIG VERB'S OWN WRITE (the kernel then ends

#[test]
fn a_push_config_write_the_store_refuses_answers_the_engines_internal_error() {
    let id = json!(7);
    for (verb, message) in [
        (
            LocalVerb::CreatePushConfig(Dialect::V10),
            "the push notification config could not be recorded",
        ),
        (
            LocalVerb::CreatePushConfig(Dialect::V03),
            "the push notification config could not be recorded",
        ),
        (
            LocalVerb::DeletePushConfig(Dialect::V10),
            "the push notification config could not be deleted; retry the delete",
        ),
        (
            LocalVerb::DeletePushConfig(Dialect::V03),
            "the push notification config could not be deleted; retry the delete",
        ),
    ] {
        let refusal = unrecorded(verb, &id).unwrap_or_else(|| panic!("{verb:?} states none"));
        assert_eq!(refusal.status, 500, "{verb:?}");
        assert_eq!(
            refusal.envelope(),
            json!({ "jsonrpc": "2.0", "id": 7, "error": { "code": -32603, "message": message } }),
            "{verb:?}"
        );
    }
    for verb in [
        LocalVerb::ListTasks,
        LocalVerb::GetPushConfig(Dialect::V10),
        LocalVerb::ListPushConfigs(Dialect::V03),
        LocalVerb::Subscribe,
    ] {
        assert_eq!(unrecorded(verb, &id), None, "{verb:?}");
    }
}

#[test]
fn list_status_uses_proto_enum_values_and_rejects_unknown_states() {
    let mut desk = desk();
    for status in [
        json!("TASK_STATE_SUBMITTED"),
        json!("submitted"),
        json!(1),
        json!(0),
        json!("TASK_STATE_UNSPECIFIED"),
    ] {
        let (http, answer) = call(&mut desk, "ListTasks", json!({"status": status}), ALICE);
        assert_eq!(http, 200);
        assert_eq!(answer["result"]["totalSize"], 2);
    }
    for status in [
        json!(true),
        json!("unknown"),
        json!(99),
        json!([]),
        json!(1.5),
    ] {
        let (_, answer) = call(&mut desk, "ListTasks", json!({"status": status}), ALICE);
        assert_eq!(error_of(&answer).0, INVALID_PARAMS);
    }
    let (_, answer) = call(&mut desk, "ListTasks", json!({"status": 3}), ALICE);
    assert_eq!(answer["result"]["totalSize"], 0);
}

#[test]
fn malformed_list_cursor_is_refused_instead_of_restarting_the_page() {
    let mut desk = desk();
    for token in [
        json!("not-a-cursor"),
        json!("NaN:t1"),
        json!("1:"),
        json!("+1:t1"),
        json!(1),
    ] {
        let (_, answer) = call(&mut desk, "ListTasks", json!({"pageToken": token}), ALICE);
        assert_eq!(error_of(&answer).0, INVALID_PARAMS);
        assert!(answer.get("result").is_none());
    }
}

#[test]
fn refused_config_replacement_and_deletion_wipe_their_exact_raw_record_copies() {
    use crate::tests::raw_custody_probe::{Probe, SECRET};
    let credential = std::str::from_utf8(SECRET).unwrap();
    let config = |id: &str| {
        json!({
            "taskId":"t1", "id":id, "url":"https://hooks.example/cb",
            "authentication":{"scheme":"Bearer", "credentials":credential},
        })
    };
    let mut desk = desk();
    assert_eq!(
        call(
            &mut desk,
            "CreateTaskPushNotificationConfig",
            config("kept"),
            ALICE
        )
        .0,
        200
    );
    for (method, params, retired) in [
        ("CreateTaskPushNotificationConfig", config("different"), 2),
        (
            "DeleteTaskPushNotificationConfig",
            json!({"taskId":"t1","id":"different"}),
            1,
        ),
    ] {
        let probe = Probe::start();
        assert!(call(&mut desk, method, params, ALICE).0 >= 400);
        assert_eq!(probe.retirements(), retired);
        probe.checkpoint();
    }
    desk.verdict = DEST_INTERNAL;
    let probe = Probe::start();
    assert_eq!(
        call(
            &mut desk,
            "CreateTaskPushNotificationConfig",
            config("kept"),
            ALICE
        )
        .0,
        400
    );
    assert_eq!(probe.retirements(), 2);
    probe.checkpoint();
    assert_eq!(
        held_config(&mut desk, ALICE, "t1").unwrap().unwrap().id,
        "kept"
    );
}
