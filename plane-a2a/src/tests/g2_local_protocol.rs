// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[test]
fn catch_all_aip193_refusals_use_the_actual_http_status_and_keep_the_error_identity() {
    for (status, name) in [
        (401, "UNAUTHENTICATED"),
        (403, "PERMISSION_DENIED"),
        (429, "RESOURCE_EXHAUSTED"),
        (503, "UNAVAILABLE"),
        (504, "DEADLINE_EXCEEDED"),
        (400, "FAILED_PRECONDITION"),
        (501, "FAILED_PRECONDITION"),
    ] {
        let refusal = AgentRefusal::new(status, Some(json!(7)), -32004, "the request was refused");
        let got = refusal.aip193();
        assert_eq!(got["error"]["code"], status);
        assert_eq!(got["error"]["status"], name);
        assert_eq!(
            got["error"]["details"][0]["reason"],
            "UNSUPPORTED_OPERATION"
        );
        assert_eq!(refusal.envelope()["error"]["code"], -32004);
    }
    assert_eq!(
        AgentRefusal::new(404, None, -32001, "missing").aip193()["error"]["status"],
        "NOT_FOUND"
    );
}

fn register(desk: &mut Desk, extra: Value) -> (u32, Value) {
    let mut config = json!({"taskId":"t1", "id":"hook-1", "url":"https://hooks.example/cb"});
    config
        .as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    call(desk, "CreateTaskPushNotificationConfig", config, ALICE)
}

#[test]
fn v03_get_push_config_distinguishes_absent_null_named_and_malformed_ids() {
    let mut desk = desk();
    assert_eq!(register(&mut desk, json!({})).0, 200);
    for params in [
        json!({"id":"t1"}),
        json!({"id":"t1", "pushNotificationConfigId":null}),
        json!({"id":"t1", "pushNotificationConfigId":"hook-1"}),
    ] {
        let (status, got) = call(&mut desk, "tasks/pushNotificationConfig/get", params, ALICE);
        assert_eq!(status, 200);
        assert_eq!(
            got["result"]["pushNotificationConfig"],
            json!({"id":"hook-1", "url":"https://hooks.example/cb"})
        );
    }
    for wrong in [json!(4), json!(false), json!([]), json!({})] {
        let (status, got) = call(
            &mut desk,
            "tasks/pushNotificationConfig/get",
            json!({"id":"t1", "pushNotificationConfigId":wrong}),
            ALICE,
        );
        assert_eq!((status, error_of(&got).0), (400, -32602));
    }
    let (status, _) = call(
        &mut desk,
        "tasks/pushNotificationConfig/get",
        json!({"id":"t1", "pushNotificationConfigId":"other"}),
        ALICE,
    );
    assert_eq!(status, 404);
    let (status, _) = call(
        &mut desk,
        "GetTaskPushNotificationConfig",
        json!({"taskId":"t1", "id":"hook-1"}),
        ALICE,
    );
    assert_eq!(status, 200, "the v1 named read is unchanged");
    let (status, _) = call(
        &mut desk,
        "tasks/pushNotificationConfig/get",
        json!({"id":"t1"}),
        BOB,
    );
    assert_eq!(status, 404, "an omitted config id never bypasses ownership");
}

#[test]
fn a_persisted_colon_bearing_task_id_pages_once_and_reaches_the_end() {
    let mut desk = Desk {
        book: Book::default(),
        verdict: DEST_ALLOWED,
        judged: Vec::new(),
    };
    for id in [
        "a2a-team:billing-1",
        "a2a-team:billing-2",
        "a2a-team:billing-3",
    ] {
        submitted(&mut desk.book, ALICE, id, 100);
    }
    let mut token = String::new();
    let mut ids = Vec::new();
    for _ in 0..3 {
        let (status, got) = call(
            &mut desk,
            "ListTasks",
            json!({"pageSize":1, "pageToken":token}),
            ALICE,
        );
        assert_eq!(status, 200);
        let page = got["result"]["tasks"].as_array().unwrap();
        assert_eq!(page.len(), 1);
        ids.push(page[0]["id"].as_str().unwrap().to_owned());
        token = got["result"]["nextPageToken"].as_str().unwrap().to_owned();
    }
    assert!(token.is_empty(), "the third page is the last");
    assert_eq!(
        ids,
        [
            "a2a-team:billing-3",
            "a2a-team:billing-2",
            "a2a-team:billing-1"
        ]
    );
}

#[test]
fn status_timestamp_filter_is_inclusive_precise_and_scoped_before_paging() {
    let mut desk = desk();
    for (name, stamp, expected) in [
        ("statusTimestampAfter", "1970-01-01T00:02:30Z", vec!["t2"]),
        ("statusTimestampAfter", "1970-01-01T00:03:20Z", vec!["t2"]),
        (
            "status_timestamp_after",
            "1970-01-01T00:03:20.000000001Z",
            vec![],
        ),
    ] {
        let (status, got) = call(
            &mut desk,
            "ListTasks",
            json!({(name):stamp, "pageSize":1}),
            ALICE,
        );
        assert_eq!(status, 200);
        let result = &got["result"];
        let ids: Vec<_> = result["tasks"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, expected);
        assert_eq!(result["totalSize"].as_u64(), Some(expected.len() as u64));
        assert_eq!(result["nextPageToken"], "");
    }
    for stamp in [json!(4), json!(false), json!({}), json!("not-a-timestamp")] {
        let (status, got) = call(
            &mut desk,
            "ListTasks",
            json!({"statusTimestampAfter":stamp}),
            ALICE,
        );
        assert_eq!((status, error_of(&got).0), (400, -32602));
    }
    for params in [json!({}), json!({"statusTimestampAfter":null})] {
        let (status, got) = call(&mut desk, "ListTasks", params, ALICE);
        assert_eq!(status, 200);
        assert_eq!(got["result"]["totalSize"], 2);
    }
}

#[test]
fn null_callback_members_do_not_require_push_but_objects_still_do() {
    use crate::skill::TaskShape;
    for key in ["pushNotificationConfig", "taskPushNotificationConfig"] {
        let none = json!({"method":"SendMessage", "params":{"configuration":{(key):null}}});
        assert!(!TaskShape::of(&none).requires_push_notifications);
        let some = json!({"method":"SendMessage", "params":{"configuration":{(key):{"url":"https://hooks.example/cb"}}}});
        assert!(TaskShape::of(&some).requires_push_notifications);
    }
    assert!(!TaskShape::of(&json!({"method":"SendMessage"})).requires_push_notifications);
}

#[test]
fn skill_refusals_are_sentences_with_the_same_status_and_protocol_code() {
    use crate::skill::{refusal, Unfit, Unreadable};
    for (unfit, words) in [
        (Unfit::SkillNotDeclared("plan".into()), "this agent's card declares no skill `plan`"),
        (Unfit::CapabilityNotDeclared("streaming"), "this agent's card does not declare the `streaming` capability this request needs"),
        (Unfit::ModesIncompatible, "this agent's card produces none of the output modes this request accepts in `acceptedOutputModes`"),
        (Unfit::Unreadable(Unreadable::NotAnObject), "this agent's held card cannot be read: it is not a JSON object"),
        (Unfit::NoCachedCard, "busbar holds no card for this agent yet, so the request cannot be judged against what the agent declares"),
    ] {
        let got = refusal(&unfit);
        assert_eq!((got.status, got.code, got.message.as_str()), (400, -32004, words));
        assert_eq!(got.envelope()["error"]["data"][0]["reason"], "UNSUPPORTED_OPERATION");
    }
}

#[test]
fn snapshots_are_not_artifact_chunks_but_each_actual_update_is() {
    for (result, artifact) in [
        (
            json!({"task":{"id":"far", "status":{"state":"TASK_STATE_WORKING"}, "artifacts":[]}}),
            false,
        ),
        (
            json!({"kind":"task", "id":"far", "status":{"state":"working"}, "artifacts":[{"artifactId":"a"}]}),
            false,
        ),
        (
            json!({"artifactUpdate":{"taskId":"far", "artifact":{"artifactId":"a", "parts":[]}}}),
            true,
        ),
        (
            json!({"kind":"artifact-update", "taskId":"far", "artifact":{"artifactId":"a", "parts":[]}}),
            true,
        ),
    ] {
        let frame = format!(
            "data: {}\n\n",
            json!({"jsonrpc":"2.0", "id":7, "result":result})
        );
        let got = crate::events::read_event(&frame, &json!(7), "owned", "ctx", None, &[]).unwrap();
        assert_eq!(got.artifact, artifact);
        assert_eq!(got.backend_task_id.as_deref(), Some("far"));
        assert!(!std::str::from_utf8(&got.sse).unwrap().contains("\"far\""));
    }
}

#[test]
fn callback_token_null_is_absent_and_non_null_tokens_are_explicitly_refused() {
    for extra in [json!({}), json!({"token":null})] {
        let mut desk = desk();
        assert_eq!(register(&mut desk, extra).0, 200);
        assert!(desk
            .book
            .value(KIND_PUSH_CONFIG, &task_key(ALICE, "t1"))
            .is_some());
    }
    for token in [
        json!("TOKEN-CANARY"),
        json!(42),
        json!(false),
        json!({}),
        json!([]),
    ] {
        let mut desk = desk();
        let (status, got) = register(&mut desk, json!({"token":token}));
        assert_eq!((status, error_of(&got).0), (400, -32004));
        assert!(error_of(&got)
            .1
            .starts_with("busbar does not carry a push notification config `token`"));
        assert!(!got.to_string().contains("TOKEN-CANARY"));
        assert!(desk.judged.is_empty());
        assert!(desk
            .book
            .value(KIND_PUSH_CONFIG, &task_key(ALICE, "t1"))
            .is_none());
    }
}

#[test]
fn malformed_callback_credentials_are_refused_before_judging_or_writing_without_echoing() {
    for credentials in [
        json!(42),
        json!(false),
        json!([]),
        json!({"CREDENTIAL-CANARY": "private"}),
    ] {
        let mut desk = desk();
        let (status, got) = register(
            &mut desk,
            json!({"authentication":{"scheme":"Bearer", "credentials":credentials}}),
        );
        assert_eq!((status, error_of(&got).0), (400, -32602));
        assert!(error_of(&got).1.contains("`credentials` must be a string"));
        assert!(!got.to_string().contains("CREDENTIAL-CANARY"));
        assert!(desk.judged.is_empty());
        assert!(desk
            .book
            .value(KIND_PUSH_CONFIG, &task_key(ALICE, "t1"))
            .is_none());
    }
    for authentication in [
        Value::Null,
        json!({"scheme":"Bearer"}),
        json!({"scheme":"Bearer", "credentials":null}),
        json!({"scheme":"Bearer", "credentials":""}),
        json!({"scheme":"Bearer", "credentials":"valid-secret"}),
    ] {
        let mut desk = desk();
        let (status, got) = register(&mut desk, json!({"authentication":authentication}));
        assert_eq!(status, 200);
        assert!(!got.to_string().contains("valid-secret"));
    }
}

#[test]
fn rest_task_paths_remove_conflicting_body_aliases_without_removing_metadata_or_config_id() {
    use crate::rest;
    let route = |suffix| {
        crate::statement::ROUTES
            .iter()
            .find(|r| r.verb == "POST" && r.target == format!("{}{suffix}", crate::MOUNT_PATH))
            .unwrap()
    };
    let cancel = rest::compose_from(
        route(crate::ROUTE_TASK),
        |_| "owned:cancel".into(),
        None,
        br#"{"id":"foreign","taskId":"foreign","task_id":"foreign","metadata":{"keep":true}}"#,
    )
    .unwrap()
    .unwrap();
    let got: Value = serde_json::from_slice(&cancel).unwrap();
    assert_eq!(
        got["params"],
        json!({"id":"owned", "metadata":{"keep":true}})
    );
    let create = rest::compose_from(route(crate::ROUTE_PUSH_CONFIGS), |_| "owned".into(), None,
        br#"{"id":"config-1","taskId":"foreign","task_id":"foreign","url":"https://hooks.example/cb"}"#).unwrap().unwrap();
    let got: Value = serde_json::from_slice(&create).unwrap();
    assert_eq!(
        got["params"],
        json!({"id":"config-1", "taskId":"owned", "url":"https://hooks.example/cb"})
    );
}

#[test]
fn many_sse_events_keep_order_all_terminators_and_the_first_error_boundary() {
    use crate::framed::{event_messages, Code, Rpc};
    use prost::Message as _;
    let mut wire = Vec::new();
    for index in 0..256 {
        let end = ["\n\n", "\r\n\r\n", "\r\r"][index % 3];
        wire.extend_from_slice(format!("data: {}{end}", json!({"jsonrpc":"2.0","id":7,"result":{"task":{"id":format!("t{index}"), "status":{"state":"TASK_STATE_WORKING"}}}})).as_bytes());
    }
    let (messages, status) = event_messages(Rpc::SendStreamingMessage, &wire);
    assert!(status.is_none());
    let ids: Vec<_> = messages
        .iter()
        .map(|m| {
            let got = crate::proto::pb::StreamResponse::decode(m.as_slice()).unwrap();
            let Some(crate::proto::pb::stream_response::Payload::Task(task)) = got.payload.as_ref()
            else {
                panic!("a task event")
            };
            task.id.clone()
        })
        .collect();
    assert_eq!(ids, (0..256).map(|n| format!("t{n}")).collect::<Vec<_>>());
    wire.extend_from_slice(b"data: {\"jsonrpc\":\"2.0\",\"id\":7,\"error\":{\"code\":-32001,\"message\":\"missing\"}}\n\n");
    wire.extend_from_slice(
        b"data: {\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{\"task\":{\"id\":\"late\"}}}\n\n",
    );
    let (messages, status) = event_messages(Rpc::SendStreamingMessage, &wire);
    assert_eq!(messages.len(), 256);
    assert_eq!(status.unwrap().code(), Code::NotFound);
}

#[test]
fn reading_copy_substitutes_only_nonfinite_numeric_tokens_and_preserves_the_original() {
    let raw = format!(
        "{{\"text\":\"1e999 \\\" -2e999\",\"counts\":[{}],\"normal\":1.25}}",
        ["1e999", "-2e999", "3"].repeat(1024).join(",")
    );
    let original = raw.clone();
    let reading = crate::answer_bytes::readable(raw.as_bytes());
    let got: Value = serde_json::from_slice(&reading).unwrap();
    assert_eq!(got["text"], "1e999 \" -2e999");
    let expected = [0, 0, 3].repeat(1024);
    assert_eq!(got["counts"], json!(expected));
    assert_eq!(got["normal"], 1.25);
    assert_eq!(raw, original);
    assert!(matches!(
        crate::answer_bytes::readable(br#"{"n":27,"text":"1e999"}"#),
        std::borrow::Cow::Borrowed(_)
    ));
}
