// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The HTTP+JSON line's arrival: the envelope each route composes (member for member the engine's

use super::*;
use crate::statement::ROUTES;
use serde_json::json;

/// The route `verb target` of the door's routes.
fn route(verb: &str, target: &str) -> &'static Route {
    ROUTES
        .iter()
        .find(|r| r.verb == verb && r.target == target)
        .expect("a door route")
}

/// The envelope `verb target` composes over `body`, read back as JSON.
fn composed(verb: &str, path: &str, target: &str, body: &[u8]) -> Value {
    let bytes = compose(route(verb, path), target, body)
        .expect("composes")
        .expect("a line route");
    serde_json::from_slice(&bytes).expect("JSON")
}

/// The envelope `{"jsonrpc","id","method","params"}` with the fixed id.
fn envelope(name: &str, params: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": REST_RPC_ID, "method": name, "params": params})
}

/// QUERY STRINGS ARE TYPED ON THE WAY INTO THE ENVELOPE. `historyLength=5` means the NUMBER five to

#[test]
fn query_values_are_typed_the_way_the_envelope_wants_them() {
    assert_eq!(json_scalar("5"), json!(5));
    assert_eq!(json_scalar("-3"), json!(-3));
    assert_eq!(json_scalar("true"), json!(true));
    assert_eq!(json_scalar("false"), json!(false));
    assert_eq!(json_scalar("ctx-1"), json!("ctx-1"));
    assert_eq!(json_scalar(""), json!(""));
}

/// ABSENT IS NOT EMPTY. A query parameter the caller omitted must not appear in the composed params

#[test]
fn an_omitted_query_parameter_is_absent_from_the_params() {
    let params = Params::new()
        .set("id", "t-1")
        .maybe("historyLength", None)
        .into_value();
    assert_eq!(params, json!({"id": "t-1"}));

    let asked = "7".to_string();
    let params = Params::new()
        .set("id", "t-1")
        .maybe("historyLength", Some(&asked))
        .into_value();
    assert_eq!(params, json!({"id": "t-1", "historyLength": 7}));
}

/// THE PATH WINS OVER THE BODY. A `taskId` member in a posted push-notification config must not

#[test]
fn a_body_member_cannot_re_point_the_addressed_task() {
    let params = Params::new()
        .merge(&json!({"taskId": "somebody-elses", "url": "https://receiver.example/hook"}))
        .set("taskId", "the-one-addressed")
        .into_value();
    assert_eq!(params["taskId"], "the-one-addressed");
    assert_eq!(params["url"], "https://receiver.example/hook");
}

/// AN EMPTY BODY IS NOT A PARSE FAILURE. `POST /tasks/{id}:cancel` carries none, and neither does a

#[test]
fn an_absent_body_composes_empty_params() {
    assert_eq!(json_body(b"").unwrap(), json!({}));
    assert_eq!(
        json_body(b"{\"message\":1}").unwrap(),
        json!({"message": 1})
    );
}

#[test]
fn malformed_or_nonobject_bodies_never_compose_a_path_addressed_operation() {
    for (pattern, target) in [
        ("/a2a/message:send", "/a2a/message:send"),
        ("/a2a/message:stream", "/a2a/message:stream"),
        ("/a2a/tasks/{id}", "/a2a/tasks/live-task:cancel"),
        (
            "/a2a/tasks/{id}/pushNotificationConfigs",
            "/a2a/tasks/live-task/pushNotificationConfigs",
        ),
    ] {
        for body in [
            b"nope".as_slice(),
            b"{broken",
            b"[]",
            b"null",
            b"false",
            b"\"scalar\"",
        ] {
            let refusal = compose(route("POST", pattern), target, body).unwrap_err();
            assert_eq!(refusal.status, 400);
            assert!(matches!(refusal.code, -32700 | -32602));
            let rendered = crate::agent_arrival::render(
                crate::agent_arrival::Dialect::RestJson,
                &refusal,
                true,
            );
            let document: Value = serde_json::from_slice(&rendered.body).unwrap();
            assert_eq!(document["error"]["status"], "INVALID_ARGUMENT");
        }
    }
}

/// EVERY ROUTE OF THE LINE composes the engine's envelope: the method its request line names, the

#[test]
fn each_route_composes_the_engines_envelope() {
    let body = br#"{"message":{"role":"ROLE_USER","parts":[]}}"#;
    assert_eq!(
        composed("POST", "/a2a/message:send", "/a2a/message:send", body),
        envelope(
            method::SEND_MESSAGE,
            json!({"message": {"role": "ROLE_USER", "parts": []}})
        )
    );
    assert_eq!(
        composed("POST", "/a2a/message:stream", "/a2a/message:stream", body)["method"],
        method::SEND_STREAM_MESSAGE
    );
    assert_eq!(
        composed(
            "GET",
            "/a2a/tasks",
            "/a2a/tasks?pageSize=5&status=working&unknown=x&includeArtifacts=true",
            b""
        ),
        envelope(
            method::LIST_TASKS,
            json!({"pageSize": 5, "status": "working", "includeArtifacts": true})
        )
    );
    assert_eq!(
        composed(
            "GET",
            "/a2a/tasks/{id}",
            "/a2a/tasks/t%2D1?historyLength=2",
            b""
        ),
        envelope(method::GET_TASK, json!({"id": "t-1", "historyLength": 2}))
    );
    assert_eq!(
        composed("POST", "/a2a/tasks/{id}", "/a2a/tasks/t-1:cancel", b""),
        envelope(method::CANCEL_TASK, json!({"id": "t-1"}))
    );
    assert_eq!(
        composed("POST", "/a2a/tasks/{id}", "/a2a/tasks/a:b:subscribe", b""),
        envelope(method::SUBSCRIBE_TO_TASK, json!({"id": "a:b"}))
    );
    let configs = "/a2a/tasks/{id}/pushNotificationConfigs";
    assert_eq!(
        composed(
            "POST",
            configs,
            "/a2a/tasks/t-1/pushNotificationConfigs",
            br#"{"taskId":"other","url":"https://r.example/h"}"#
        ),
        envelope(
            method::CREATE_PUSH_CONFIG,
            json!({"taskId": "t-1", "url": "https://r.example/h"})
        )
    );
    assert_eq!(
        composed(
            "GET",
            configs,
            "/a2a/tasks/t-1/pushNotificationConfigs?pageToken=p+2",
            b""
        ),
        envelope(
            method::LIST_PUSH_CONFIGS,
            json!({"taskId": "t-1", "pageToken": "p 2"})
        )
    );
    let config = "/a2a/tasks/{id}/pushNotificationConfigs/{config_id}";
    let one = "/a2a/tasks/t-1/pushNotificationConfigs/c-9";
    assert_eq!(
        composed("GET", config, one, b""),
        envelope(
            method::GET_PUSH_CONFIG,
            json!({"taskId": "t-1", "id": "c-9"})
        )
    );
    assert_eq!(
        composed("DELETE", config, one, b""),
        envelope(
            method::DELETE_PUSH_CONFIG,
            json!({"taskId": "t-1", "id": "c-9"})
        )
    );
    assert_eq!(
        composed(
            "GET",
            "/a2a/extendedAgentCard",
            "/a2a/extendedAgentCard",
            b""
        ),
        envelope(method::GET_EXTENDED_AGENT_CARD, json!({}))
    );
}

/// A `POST /tasks/{id}` NAMING NO VERB is the engine's `404` + `MethodNotFound`, in its words, before

#[test]
fn a_task_post_naming_no_verb_is_the_engines_404() {
    let task = route("POST", "/a2a/tasks/{id}");
    for target in ["/a2a/tasks/t-1", "/a2a/tasks/t-1:archive"] {
        let refusal = compose(task, target, b"").expect_err("refused");
        assert_eq!(
            (refusal.status, refusal.code, refusal.id.clone()),
            (404, -32601, None)
        );
        let addressed = target.trim_start_matches("/a2a/tasks/");
        assert_eq!(
            refusal.message,
            format!(
                "`{addressed}` names no operation on this binding; the task operations are \
                 `{{id}}:cancel` and `{{id}}:subscribe`"
            )
        );
        assert_eq!(refusal.aip193()["error"]["status"], "UNIMPLEMENTED");
    }
    assert_eq!(compose(task, "/a2a/tasks", b""), Ok(None));
    assert_eq!(compose(route("POST", "/a2a"), "/a2a", b"{}"), Ok(None));
}

/// A PATH CAPTURE IS DECODED AS THE ROUTER DECODED IT: `%XX` is the byte and `+` stays a `+`; a

#[test]
fn path_captures_decode_as_the_router_did() {
    assert_eq!(path_decode("a%3Ab+c").as_deref(), Some("a:b+c"));
    assert_eq!(path_decode("%zz%4").as_deref(), Some("%zz%4"));
    assert_eq!(path_decode("%FF"), None);
    let task = route("GET", "/a2a/tasks/{id}");
    for target in ["/a2a/tasks/%FF", "/a2a/tasks/%C3%28"] {
        let refusal = compose(task, target, b"").expect_err("invalid UTF-8 capture");
        assert_eq!(
            (refusal.status, refusal.code, refusal.id),
            (400, -32602, None)
        );
        assert_eq!(
            refusal.message,
            "the `id` path capture must decode as UTF-8"
        );
    }

    let config = route("GET", "/a2a/tasks/{id}/pushNotificationConfigs/{config_id}");
    assert_eq!(compose(config, "/a2a/tasks/%FF/other/%FF", b""), Ok(None));
    let refusal = compose(config, "/a2a/tasks/t/pushNotificationConfigs/%FF", b"")
        .expect_err("invalid config id");
    assert_eq!(
        refusal.message,
        "the `config_id` path capture must decode as UTF-8"
    );
    assert_eq!(
        composed("GET", "/a2a/tasks/{id}", "/a2a/tasks/%E2%9C%93+a", b"")["params"]["id"],
        "✓+a"
    );
}

/// A QUERY COMPONENT IS DECODED AS `Query` DECODED IT: `+` is a space, `%XX` the byte, a repeated

#[test]
fn query_components_decode_as_the_extractor_did() {
    let q = query_map(Some("a=1+2&b=%41&a=3&&c")).unwrap();
    assert_eq!(q.get("a").map(String::as_str), Some("3"));
    assert_eq!(q.get("b").map(String::as_str), Some("A"));
    assert_eq!(q.get("c").map(String::as_str), Some(""));
    assert!(query_map(None).unwrap().is_empty());
}

/// RE-FRAMED BY WHAT IT IS: a result is the body verbatim, an error the AIP-193 document at the

#[test]
fn an_answer_is_reframed_by_what_it_is() {
    let result = br#"{"jsonrpc":"2.0","id":"a2a-http-json","result":{"tasks":[]}}"#;
    assert_eq!(reframe(200, result), br#"{"tasks":[]}"#.to_vec());
    let error = br#"{"jsonrpc":"2.0","id":null,"error":{"code":-32001,"message":"no such task","data":[{"reason":"TASK_NOT_FOUND"}]}}"#;
    let doc: Value = serde_json::from_slice(&reframe(404, error)).expect("JSON");
    assert_eq!(
        doc,
        json!({"error": {"code": 404, "status": "NOT_FOUND", "message": "no such task",
            "details": [{"reason": "TASK_NOT_FOUND"}]}})
    );
    let other = br#"{"status":"unavailable"}"#;
    assert_eq!(reframe(503, other), other.to_vec());
    assert_eq!(reframe(502, b"not json"), b"not json".to_vec());
}

#[test]
fn an_agent_error_without_a_readable_message_keeps_its_code_and_details() {
    for error in [
        json!({"code": -32001, "data": [{"reason": "TASK_NOT_FOUND"}]}),
        json!({"code": -32001, "message": 5, "data": [{"reason": "TASK_NOT_FOUND"}]}),
    ] {
        let body = serde_json::to_vec(&json!({"error": error})).unwrap();
        let doc: Value = serde_json::from_slice(&reframe(404, &body)).unwrap();
        assert_eq!(doc["error"]["code"], 404);
        assert_eq!(doc["error"]["status"], "NOT_FOUND");
        assert_eq!(
            doc["error"]["details"],
            json!([{"reason": "TASK_NOT_FOUND"}])
        );
        assert_eq!(
            doc["error"]["message"],
            "the agent returned an error without a readable message"
        );
    }
    for body in [br#"{"error":5}"#.as_slice(), br#"{"error":[]}"#.as_slice()] {
        let doc: Value = serde_json::from_slice(&reframe(502, body)).unwrap();
        assert_eq!(doc["error"]["code"], 502);
        assert!(!doc["error"]["message"].as_str().unwrap().is_empty());
    }
    for message in ["a supplied explanation", ""] {
        let body =
            serde_json::to_vec(&json!({"error":{"code": -32001, "message":message}})).unwrap();
        let doc: Value = serde_json::from_slice(&reframe(404, &body)).unwrap();
        assert_eq!(doc["error"]["message"], message);
    }
}

#[test]
fn an_unreadable_agent_error_is_preserved_without_fabricating_an_empty_error() {
    let mut deep = br#"{"error":{"message":"agent explanation","data":"#.to_vec();
    deep.extend(std::iter::repeat_n(b'[', 150));
    deep.push(b'0');
    deep.extend(std::iter::repeat_n(b']', 150));
    deep.extend_from_slice(b"}}");
    for body in [
        deep,
        br#"{"error":{"message":"\uD800"}}"#.to_vec(),
        b"{\"error\":{\"message\":\"\xff\"}}".to_vec(),
        br#"{"error":null}"#.to_vec(),
    ] {
        assert_eq!(reframe(502, &body), body);
    }
}

/// THE RESULT IS THE ANSWER'S OWN BYTES (Law 5): member order, an integer past 64 bits and a

#[test]
fn a_result_is_the_answers_own_bytes() {
    let answer = br#"{"jsonrpc":"2.0","id":"a2a-http-json","result":{"z":1, "id":"a2a-p-1","n":123456789012345678901234567890,"big":1e400}}"#;
    assert_eq!(
        String::from_utf8(reframe(200, answer)).unwrap(),
        r#"{"z":1, "id":"a2a-p-1","n":123456789012345678901234567890,"big":1e400}"#
    );
}

/// Ported from busbar-a2a a2a/tests/rest_tests.rs::a_string_coded_refusal_re_frames_from_its_http_status.

#[test]
fn a_string_coded_refusal_re_frames_from_its_http_status() {
    let doc = br#"{"error":{"code":"unavailable","message":"no card yet"}}"#;
    let body: Value = serde_json::from_slice(&reframe(503, doc)).expect("JSON");
    assert_eq!(
        body["error"]["code"],
        json!(503),
        "a string-coded refusal still re-frames its code to the HTTP status"
    );
    assert_eq!(body["error"]["status"], "UNAVAILABLE");
    assert_eq!(body["error"]["message"], "no card yet");
}

/// SUBSCRIBE IS A GET (proto `SubscribeToTask`: `get: "/tasks/{id=*}:subscribe"`). The verb suffix

#[test]
fn a_get_of_a_tasks_subscribe_suffix_is_subscribe_to_task() {
    let task = "/a2a/tasks/{id}";
    assert_eq!(
        composed("GET", task, "/a2a/tasks/abc:subscribe", b""),
        envelope(method::SUBSCRIBE_TO_TASK, json!({"id": "abc"}))
    );
    assert_eq!(
        composed("GET", task, "/a2a/tasks/a:b:subscribe", b""),
        envelope(method::SUBSCRIBE_TO_TASK, json!({"id": "a:b"}))
    );
    assert_eq!(
        composed("GET", task, "/a2a/tasks/abc", b""),
        envelope(method::GET_TASK, json!({"id": "abc"}))
    );
}

/// A CANCEL'S BODY IS ITS PARAMS (proto `CancelTask`: `post: "/tasks/{id=*}:cancel" body: "*"`), so

#[test]
fn a_posted_cancel_body_reaches_the_params_and_the_path_wins() {
    assert_eq!(
        composed(
            "POST",
            "/a2a/tasks/{id}",
            "/a2a/tasks/t-1:cancel",
            br#"{"id":"somebody-elses","metadata":{"why":"done"}}"#
        ),
        envelope(
            method::CANCEL_TASK,
            json!({"id": "t-1", "metadata": {"why": "done"}})
        )
    );
}

/// ONLY THE PROTO'S NON-STRING QUERY MEMBERS ARE TYPED. `contextId`, `pageToken`, `status` and

#[test]
fn only_the_protos_non_string_query_members_are_typed() {
    assert_eq!(
        composed(
            "GET",
            "/a2a/tasks",
            "/a2a/tasks?contextId=12345&pageToken=007&status=true&statusTimestampAfter=1\
             &pageSize=5&historyLength=2&includeArtifacts=false",
            b""
        ),
        envelope(
            method::LIST_TASKS,
            json!({
                "contextId": "12345",
                "pageToken": "007",
                "status": "true",
                "statusTimestampAfter": "1",
                "pageSize": 5,
                "historyLength": 2,
                "includeArtifacts": false,
            })
        )
    );
    assert_eq!(
        composed(
            "GET",
            "/a2a/tasks/{id}/pushNotificationConfigs",
            "/a2a/tasks/t-1/pushNotificationConfigs?pageToken=42&pageSize=3",
            b""
        ),
        envelope(
            method::LIST_PUSH_CONFIGS,
            json!({"taskId": "t-1", "pageToken": "42", "pageSize": 3})
        )
    );
}

#[test]
fn rest_queries_refuse_invalid_utf8_and_wrong_proto_scalar_types() {
    let list = route("GET", "/a2a/tasks");
    for query in [
        "pageToken=%FF",
        "contextId=%C0%AF",
        "includeArtifacts=1",
        "pageSize=true",
        "historyLength=2147483648",
    ] {
        let error = compose(list, &format!("/a2a/tasks?{query}"), b"").unwrap_err();
        assert_eq!((error.status, error.code), (400, -32602));
    }
    let value = composed(
        "GET",
        "/a2a/tasks",
        "/a2a/tasks?includeArtifacts=true&pageSize=2&pageToken=%EF%BF%BD",
        b"",
    );
    assert_eq!(value["params"]["includeArtifacts"], true);
    assert_eq!(value["params"]["pageSize"], 2);
    assert_eq!(value["params"]["pageToken"], "\u{fffd}");
}
