// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! busbar's task identity on a relayed hop, against the served engine's own cases
//! (`busbar-a2a` `relay::rewrite_identity`, `idmap::translate_request`, `rpcerror::about_task`).

use super::*;
use serde_json::json;

/// [`translate_request`] over `envelope`'s bytes.
fn translated(envelope: &Value, back: &dyn Fn(&str) -> Option<String>) -> Option<Vec<u8>> {
    translate_request(&serde_json::to_vec(envelope).expect("json"), back)
}

#[test]
fn a_minted_id_is_the_engines_shape_over_the_random_bytes() {
    let id = mint("planner", [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);
    assert_eq!(id, "a2a-planner-0123456789abcdef");
    assert_eq!(mint("p", [0; MINT_BYTES]), "a2a-p-0000000000000000");
}

#[test]
fn a_bare_task_result_takes_busbars_id_and_context_and_keeps_everything_else() {
    let mut result = json!({
        "kind": "task", "id": "backend-7", "contextId": "backend-ctx",
        "status": { "state": "completed" }, "artifacts": [{ "parts": [] }],
    });
    assert!(rewrite_identity(&mut result, "a2a-p-1", "ctx-1", None, &[]));
    assert_eq!(
        result,
        json!({
            "kind": "task", "id": "a2a-p-1", "contextId": "ctx-1",
            "status": { "state": "completed" }, "artifacts": [{ "parts": [] }],
        })
    );
}

#[test]
fn a_wrapped_result_is_rewritten_inside_its_wrapper_by_its_own_identity_member() {
    let mut task = json!({ "task": { "id": "b", "contextId": "bc" } });
    assert!(rewrite_identity(&mut task, "t", "c", None, &[]));
    assert_eq!(task, json!({ "task": { "id": "t", "contextId": "c" } }));

    let mut update = json!({ "statusUpdate": { "taskId": "b", "contextId": "bc",
        "status": { "message": { "taskId": "b", "contextId": "bc", "messageId": "m" } } } });
    assert!(rewrite_identity(&mut update, "t", "c", None, &[]));
    assert_eq!(
        update,
        json!({ "statusUpdate": { "taskId": "t", "contextId": "c",
            "status": { "message": { "taskId": "t", "contextId": "c", "messageId": "m" } } } })
    );
}

#[test]
fn a_standalone_message_is_given_no_task_and_one_in_a_task_is_given_busbars() {
    let mut alone = json!({ "message": { "messageId": "m", "contextId": "bc" } });
    assert!(rewrite_identity(&mut alone, "t", "c", None, &[]));
    assert_eq!(
        alone,
        json!({ "message": { "messageId": "m", "contextId": "c" } })
    );
    let mut owned = json!({ "message": { "messageId": "m", "taskId": "b" } });
    assert!(rewrite_identity(&mut owned, "t", "c", None, &[]));
    assert_eq!(
        owned,
        json!({ "message": { "messageId": "m", "taskId": "t", "contextId": "c" } })
    );
}

#[test]
fn the_matched_skill_is_namespaced_metadata_and_a_non_object_result_is_refused() {
    let mut result = json!({ "id": "b", "metadata": { "theirs": 1 } });
    assert!(rewrite_identity(
        &mut result,
        "t",
        "c",
        Some("summarize"),
        &[]
    ));
    assert_eq!(
        result,
        json!({ "id": "t", "contextId": "c",
            "metadata": { "theirs": 1, "busbar/skill": "summarize" } })
    );
    // A far end's string, array or number is no task: the plane cannot read it, and invents none
    // (Law 11). RED: it was replaced with `{"kind":"task"}` under busbar's identity.
    for far in [json!("done"), json!([1]), json!(7), json!(null)] {
        let mut result = far.clone();
        assert!(!rewrite_identity(&mut result, "t", "c", None, &[]), "{far}");
        assert_eq!(result, far, "left as the far end sent it");
    }
}

#[test]
fn the_far_ends_id_and_state_are_read_in_both_vocabularies() {
    assert_eq!(
        backend_task_id(&json!({ "task": { "id": "b-1" } })).as_deref(),
        Some("b-1")
    );
    assert_eq!(
        backend_task_id(&json!({ "statusUpdate": { "taskId": "b-2" } })).as_deref(),
        Some("b-2")
    );
    assert_eq!(backend_task_id(&json!({ "id": "" })), None);
    assert_eq!(
        reported_task_state(&json!({ "status": { "state": "input-required" } })),
        Some(TaskState::InputRequired)
    );
    assert_eq!(
        reported_task_state(&json!({ "task": { "status": { "state": "TASK_STATE_COMPLETED" } } })),
        Some(TaskState::Completed)
    );
    // No state this build can read is no state: never a guessed `working`.
    for none in [
        json!({ "status": { "state": "pondering" } }),
        json!({ "artifactUpdate": { "taskId": "b", "artifact": {} } }),
        json!({ "kind": "message", "messageId": "m" }),
        json!({}),
    ] {
        assert_eq!(reported_task_state(&none), None, "{none}");
    }
}

#[test]
fn a_held_id_is_translated_at_the_top_and_in_the_message_and_nothing_else_is() {
    let back = |id: &str| (id == "a2a-p-1").then(|| "b-1".to_string());
    let get =
        json!({ "jsonrpc": "2.0", "id": 1, "method": "GetTask", "params": { "id": "a2a-p-1" } });
    let sent: Value = serde_json::from_slice(&translated(&get, &back).unwrap()).unwrap();
    assert_eq!(sent["params"]["id"], "b-1");

    let turn = json!({ "jsonrpc": "2.0", "id": 2, "method": "SendMessage",
        "params": { "message": { "messageId": "a2a-p-1", "taskId": "a2a-p-1" } } });
    let sent: Value = serde_json::from_slice(&translated(&turn, &back).unwrap()).unwrap();
    assert_eq!(sent["params"]["message"]["taskId"], "b-1");
    assert_eq!(sent["params"]["message"]["messageId"], "a2a-p-1");

    let foreign =
        json!({ "jsonrpc": "2.0", "id": 3, "method": "GetTask", "params": { "id": "x" } });
    assert_eq!(translated(&foreign, &back), None);
}

#[test]
fn the_named_tasks_and_context_are_read_where_the_engine_reads_them() {
    let env = json!({ "params": { "id": "a", "taskId": "b", "task_id": "c",
        "message": { "taskId": "d", "contextId": "ctx" } } });
    assert_eq!(named_tasks(&env), vec!["a", "b", "c"]);
    assert_eq!(translatable(&env), vec!["a", "b", "c", "d"]);
    assert_eq!(context_of(&env), "ctx");
    assert_eq!(context_of(&json!({ "params": {} })), "");
}

#[test]
fn a_refusal_about_a_task_carries_its_resource_info_after_the_error_info() {
    let refusal = AgentRefusal {
        status: 502,
        id: Some(json!(9)),
        code: -32006,
        message: "the backend agent did not complete this task".into(),
    };
    assert_eq!(
        about_task(&refusal, "a2a-p-1"),
        json!({
            "jsonrpc": "2.0", "id": 9,
            "error": {
                "code": -32006,
                "message": "the backend agent did not complete this task",
                "data": [
                    { "@type": "type.googleapis.com/google.rpc.ErrorInfo",
                      "domain": "a2a-protocol.org", "reason": "INVALID_AGENT_RESPONSE" },
                    { "@type": "type.googleapis.com/google.rpc.ResourceInfo",
                      "resourceType": "a2a.busbar/task", "resourceName": "a2a-p-1" },
                ],
            },
        })
    );
}

#[test]
fn the_codes_a_far_end_may_answer_keep_section_5_4s_statuses() {
    assert_eq!(status_of_code(-32001), Some(404));
    assert_eq!(status_of_code(-32002), Some(409));
    assert_eq!(status_of_code(-32005), Some(415));
    assert_eq!(status_of_code(-32602), Some(400));
    assert_eq!(status_of_code(-32603), Some(500));
    assert_eq!(status_of_code(-32050), None);
}

/// The verbs that are ABOUT a task name it `taskId` (and A2A v1.0's JSON-RPC binding also accepts
/// `task_id`; `GetTask` and `CancelTask` say `id`). All three spellings translate.
/// Ported from busbar-a2a a2a/tests/idmap_tests.rs::every_spelling_of_the_task_member_is_translated.
#[test]
fn every_spelling_of_the_task_member_is_translated() {
    let back = |id: &str| (id == "busbar-t").then(|| "backend-t".to_string());
    for member in ["id", "taskId", "task_id"] {
        let out = translated(
            &json!({
                "method": "GetTask",
                "params": { member: "busbar-t", "keep": 3 }
            }),
            &back,
        )
        .unwrap_or_else(|| panic!("`{member}` must translate"));
        let doc: Value = serde_json::from_slice(&out).expect("json");
        assert_eq!(doc["params"][member], "backend-t", "{member}");
        // Everything else survives: the translation is about identity and about nothing else.
        assert_eq!(doc["params"]["keep"], 3, "{member}");
        assert_eq!(doc["method"], "GetTask", "{member}");
    }
}

/// Nothing degenerate is recorded: a far end that named no task id (an empty one) leaves nothing to
/// map, so the id the door would record is absent, and an empty pair is never an identity.
/// Ported from busbar-a2a a2a/tests/idmap_tests.rs::a_degenerate_pair_is_not_recorded.
#[test]
fn a_degenerate_pair_is_not_recorded() {
    for result in [
        json!({ "id": "" }),
        json!({ "task": { "id": "" } }),
        json!({ "statusUpdate": { "taskId": "" } }),
        json!({}),
    ] {
        assert_eq!(backend_task_id(&result), None, "{result}");
    }
    assert_eq!(
        backend_task_id(&json!({ "id": "far-1" })).as_deref(),
        Some("far-1")
    );
}

/// A MESSAGE'S OWN `id` IS NOT A TASK ID and must never be rewritten as one: a translation that
/// reached for every member called `id` would corrupt an identity this map knows nothing about.
/// Ported from busbar-a2a a2a/tests/idmap_tests.rs::a_messages_own_id_member_is_left_alone.
#[test]
fn a_messages_own_id_member_is_left_alone() {
    let back = |id: &str| (id == "busbar-not-a-message-id").then(|| "backend-x".to_string());
    let envelope = json!({ "params": { "message": { "id": "busbar-not-a-message-id" } } });
    assert!(
        translatable(&envelope).is_empty(),
        "a message's `id` is not a task id and none is offered for translation"
    );
    assert_eq!(
        translated(&envelope, &back),
        None,
        "nothing may be translated from a message's `id`"
    );
}
/// Ported from busbar-a2a a2a/tests/rpcerror_tests.rs::the_codes_and_statuses_are_the_specifications_own.
#[test]
fn the_codes_a_far_end_may_answer_keep_section_5_4s_status_table_row_for_row() {
    // Transcribed from A2A section 5.4. Written out rather than derived, so a future edit that
    // changes a status has to change this table too.
    for (code, status) in [
        (-32001, 404),
        (-32002, 409),
        (-32003, 400),
        (-32004, 400),
        (-32005, 415),
        (-32006, 502),
        (-32007, 400),
        (-32008, 400),
        (-32009, 400),
        (-32600, 400),
        (-32601, 404),
        (-32602, 400),
        (-32603, 500),
        (-32700, 400),
    ] {
        assert_eq!(status_of_code(code), Some(status), "{code}");
    }
    // The A2A-specific band is the table the plane publishes: every code in it has a status.
    for (code, _) in crate::ERRORS {
        assert!(status_of_code(*code).is_some(), "{code}");
    }
}

/// Ported from busbar-a2a a2a/tests/rpcerror_tests.rs::push_notification_not_supported_and_extension_support_required_round_trip.
/// `-32003` and `-32008` are defined codes (HTTP 400, each with its reason): a code table that
/// skipped from `-32002` to `-32004` collapsed a relayed backend's refusal to a gateway fault.
#[test]
fn push_notification_not_supported_and_extension_support_required_round_trip() {
    for (code, reason) in [
        (-32003, "PUSH_NOTIFICATION_NOT_SUPPORTED"),
        (-32008, "EXTENSION_SUPPORT_REQUIRED"),
    ] {
        assert_eq!(status_of_code(code), Some(400), "{code} is HTTP 400");
        assert_eq!(
            crate::ERRORS
                .iter()
                .find(|(c, _)| *c == code)
                .map(|(_, r)| *r),
            Some(reason),
            "{code} reason"
        );
        let wire = crate::jsonrpc::error(&json!(1), code, "words").expect("encodes");
        let wire: serde_json::Value = serde_json::from_slice(&wire).expect("json");
        assert_eq!(wire["error"]["code"], code);
        assert_eq!(wire["error"]["data"][0]["reason"], reason);
        assert_ne!(code, -32006, "must not collapse to the gateway-fault code");
    }
}

/// A TASK'S HISTORY leaves under busbar's identity too: every message in `history` that names the
/// far end's task or context names busbar's, so no backend id reaches the caller; a message that
/// names neither is left alone.
#[test]
fn a_tasks_history_messages_take_busbars_identity() {
    let mut task = json!({ "task": { "id": "far-1", "contextId": "far-c",
        "status": { "state": "TASK_STATE_WORKING" },
        "history": [
            { "messageId": "m1", "role": "ROLE_USER", "taskId": "far-1", "contextId": "far-c" },
            { "messageId": "m2", "role": "ROLE_AGENT", "taskId": "far-1" },
            { "messageId": "m3", "role": "ROLE_AGENT" },
        ] } });
    assert!(rewrite_identity(&mut task, "t", "c", None, &[]));
    assert_eq!(
        task["task"]["history"],
        json!([
            { "messageId": "m1", "role": "ROLE_USER", "taskId": "t", "contextId": "c" },
            { "messageId": "m2", "role": "ROLE_AGENT", "taskId": "t" },
            { "messageId": "m3", "role": "ROLE_AGENT" },
        ])
    );
    let mut bare = json!({ "kind": "task", "id": "far-1", "contextId": "far-c",
        "history": [{ "kind": "message", "messageId": "m1", "taskId": "far-1", "contextId": "far-c" }] });
    assert!(rewrite_identity(&mut bare, "t", "c", None, &[]));
    assert_eq!(
        bare["history"],
        json!([{ "kind": "message", "messageId": "m1", "taskId": "t", "contextId": "c" }])
    );
}

/// A v1.0 PUSH-CONFIG VERB'S `id` IS THE CONFIG, NOT THE TASK (a2a.proto:716-733: `task_id = 2`,
/// `id = 3`): it is neither a task the request names nor one translated, even when it equals a
/// held task's id. v0.3's `id` is the task.
#[test]
fn a_push_config_verbs_config_id_is_not_a_task() {
    for method in [
        "GetTaskPushNotificationConfig",
        "DeleteTaskPushNotificationConfig",
    ] {
        let env = json!({ "method": method, "params": { "taskId": "t1", "id": "c1" } });
        assert_eq!(named_tasks(&env), vec!["t1"], "{method}");
        let same = json!({ "method": method, "params": { "taskId": "t1", "id": "t1" } });
        let sent: Value = serde_json::from_slice(
            &translated(&same, &|id| (id == "t1").then(|| "far-t1".to_string()))
                .expect("the task is translated"),
        )
        .unwrap();
        assert_eq!(sent["params"]["taskId"], "far-t1", "{method}");
        assert_eq!(
            sent["params"]["id"], "t1",
            "{method}: the config id is left alone"
        );
    }
    let v03 = json!({ "method": "tasks/pushNotificationConfig/get",
        "params": { "id": "t1", "pushNotificationConfigId": "c1" } });
    assert_eq!(named_tasks(&v03), vec!["t1"]);
}

/// A TRANSLATED REQUEST IS THE CALLER'S OWN BYTES with only the translated ids spliced (Law 5):
/// member order, an integer past 64 bits and a number past `f64`'s range go on as the caller wrote
/// them. RED: the whole envelope was re-serialised through a JSON value (members re-sorted, the
/// long integer rounded), and a number past `f64`'s range dropped the translation.
#[test]
fn a_translated_request_keeps_the_callers_bytes_but_the_ids() {
    let back = |id: &str| (id == "a2a-p-1").then(|| "b-1".to_string());
    let caller = br#"{"params": {"z":1,"message":{"taskId":"a2a-p-1","n":123456789012345678901234567890,"big":1e400,"referenceTaskIds":["a2a-p-1","x"]},"a":2.50},"method":"SendMessage","id":1,"jsonrpc":"2.0"}"#;
    let sent = translate_request(caller, &back).expect("translated");
    assert_eq!(
        String::from_utf8(sent).unwrap(),
        r#"{"params": {"z":1,"message":{"taskId":"b-1","n":123456789012345678901234567890,"big":1e400,"referenceTaskIds":["b-1","x"]},"a":2.50},"method":"SendMessage","id":1,"jsonrpc":"2.0"}"#
    );
    let get = br#"{ "id" : 9, "params" : { "id" : "a2a-p-1" }, "method" : "GetTask" }"#;
    assert_eq!(
        translate_request(get, &back).as_deref(),
        Some(br#"{ "id" : 9, "params" : { "id" : "b-1" }, "method" : "GetTask" }"#.as_slice())
    );
}

/// AN UNWRAPPED v0.3 RESULT NAMES ITS TASK BY THE MEMBER ITS `kind` SAYS: a task its `id`; a
/// message, a status update and an artifact update their `taskId`. busbar's id replaces the far
/// end's there, no stray `id` is added, and the far end's own id is read from there. RED: an
/// unwrapped update kept the far end's `taskId`, gained an `id`, and its far-end id was never read.
#[test]
fn an_unwrapped_v0_3_result_names_its_task_by_the_member_its_kind_says() {
    for kind in ["status-update", "artifact-update"] {
        let mut update = json!({ "kind": kind, "taskId": "far-1", "contextId": "far-c",
            "status": { "state": "working" }, "final": false });
        assert_eq!(backend_task_id(&update).as_deref(), Some("far-1"), "{kind}");
        assert!(rewrite_identity(&mut update, "t", "c", None, &[]));
        assert_eq!(
            update,
            json!({ "kind": kind, "taskId": "t", "contextId": "c",
                "status": { "state": "working" }, "final": false }),
            "{kind}"
        );
    }
    let mut message = json!({ "kind": "message", "messageId": "m", "taskId": "far-1" });
    assert_eq!(backend_task_id(&message).as_deref(), Some("far-1"));
    assert!(rewrite_identity(&mut message, "t", "c", None, &[]));
    assert_eq!(
        message,
        json!({ "kind": "message", "messageId": "m", "taskId": "t", "contextId": "c" })
    );
    let mut alone = json!({ "kind": "message", "messageId": "m" });
    assert_eq!(backend_task_id(&alone), None);
    assert!(rewrite_identity(&mut alone, "t", "c", None, &[]));
    assert_eq!(
        alone,
        json!({ "kind": "message", "messageId": "m", "contextId": "c" })
    );
    let mut task = json!({ "kind": "task", "id": "far-1" });
    assert!(rewrite_identity(&mut task, "t", "c", None, &[]));
    assert_eq!(task, json!({ "kind": "task", "id": "t", "contextId": "c" }));
}

/// A MESSAGE'S REFERENCED TASKS ARE TRANSLATED BOTH WAYS (`Message.reference_task_ids`,
/// a2a.proto:276): on the way out busbar's ids the caller holds become the far end's; on the way
/// back the far end's id for this task, or for a task the request referred to, becomes busbar's,
/// and an id busbar does not know is left as it is. RED: no code read `referenceTaskIds`.
#[test]
fn a_messages_referenced_tasks_are_translated_both_ways() {
    let back = |id: &str| (id == "a2a-p-1").then(|| "b-1".to_string());
    let turn = json!({ "jsonrpc": "2.0", "id": 2, "method": "message/send",
        "params": { "message": { "messageId": "m", "referenceTaskIds": ["a2a-p-1", "x"] } } });
    let sent: Value = serde_json::from_slice(&translated(&turn, &back).unwrap()).unwrap();
    assert_eq!(
        sent["params"]["message"]["referenceTaskIds"],
        json!(["b-1", "x"])
    );

    let references = [("b-1".to_string(), "a2a-p-1".to_string())];
    let mut answer = json!({ "kind": "message", "messageId": "r", "taskId": "far-7",
        "referenceTaskIds": ["far-7", "b-1", "unknown"] });
    assert!(rewrite_identity(&mut answer, "t", "c", None, &references));
    assert_eq!(
        answer["referenceTaskIds"],
        json!(["t", "a2a-p-1", "unknown"])
    );
    let mut task = json!({ "task": { "id": "far-7", "history": [
        { "messageId": "h", "reference_task_ids": ["b-1", "far-7"] } ] } });
    assert!(rewrite_identity(&mut task, "t", "c", None, &references));
    assert_eq!(
        task["task"]["history"][0]["reference_task_ids"],
        json!(["a2a-p-1", "t"])
    );
}
