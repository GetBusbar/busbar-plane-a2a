// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The unary hop, piece by piece: the request each attempt sends, the body relayed verbatim,
//! and the caller's answer in the served engine's bytes (`busbar-a2a` `relay`,
//! `refusal_client`, `receive::refuse_hop_early`).

use super::*;

#[path = "relay_raw_custody.rs"]
mod raw_custody;

#[path = "relay_failure_diagnostic_cases.rs"]
mod relay_failure_diagnostic_cases;
use crate::tests::capture::Capture;
use serde_json::json;

#[path = "relay_g2_tests.rs"]
mod relay_g2_tests;

#[path = "relay_diagnostic_cases.rs"]
mod relay_diagnostic_cases;

#[path = "relay_cut_controls.rs"]
mod relay_cut_controls;

const URL: &str = "https://vendor.example/a2a/v1?tenant=t1";
const ASK: &[u8] = br#"{"jsonrpc":"2.0","id":7,"method":"GetExtendedAgentCard"}"#;

pub(super) fn kernel(url: Option<&str>) -> Piece<'_> {
    Piece {
        from: From::Kernel(url),
        bytes: &[],
        status: None,
        last: false,
    }
}

pub(super) fn caller(bytes: &[u8]) -> Piece<'_> {
    Piece {
        from: From::Caller,
        bytes,
        status: None,
        last: true,
    }
}

pub(super) fn far(status: Option<u32>, bytes: &[u8], last: bool) -> Piece<'_> {
    Piece {
        from: From::FarEnd,
        bytes,
        status,
        last,
    }
}

/// A hop through its attempt and the caller's body, waiting on the far end.
fn sent() -> HopRelay {
    let mut r = HopRelay::new(json!(7), "1.0");
    assert!(matches!(
        r.on_piece(kernel(Some(URL))),
        PieceAnswer::Attempt(_)
    ));
    assert_eq!(r.on_piece(caller(ASK)), PieceAnswer::ToFarEndLent);
    r
}

fn answered(r: &mut HopRelay, status: u32, body: &[u8]) -> RelayReply {
    match r.on_piece(far(Some(status), body, true)) {
        PieceAnswer::ToCaller(reply) => reply,
        other => panic!("no answer: {other:?}"),
    }
}

/// The engine's refused-hop body for `code` and `sentence`, under id 7.
fn refused(code: &str, sentence: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "id": 7,
        "error": {
            "code": -32006,
            "message": format!("{code}: {sentence}"),
            "data": [{
                "@type": "type.googleapis.com/google.rpc.ErrorInfo",
                "domain": "a2a-protocol.org",
                "reason": "INVALID_AGENT_RESPONSE",
            }],
        },
    }))
    .expect("json")
}

#[test]
fn an_attempt_posts_to_the_agents_own_path_with_the_engines_three_fields_in_order() {
    let mut r = HopRelay::new(json!(7), "1.0");
    assert_eq!(
        r.on_piece(kernel(Some(URL))),
        PieceAnswer::Attempt(Attempt {
            verb: "POST",
            target: "/a2a/v1?tenant=t1".to_string(),
            fields: vec![
                ("content-type", "application/json".into()),
                ("accept", "application/json".into()),
                ("a2a-version", "1.0".into()),
            ],
        })
    );
}

#[test]
fn an_agent_url_with_no_path_is_posted_to_at_its_root() {
    assert_eq!(target_of("https://vendor.example").as_deref(), Some("/"));
    assert_eq!(target_of("not a url"), None);
}

/// The target read off a url's own bytes is the one a parse serializes, for every url the fast
/// read takes, and a url it does not take is parsed: the answer never depends on which ran.
#[test]
fn a_target_read_without_a_parse_is_the_parsed_target() {
    let parsed = |url: &str| {
        let u = url::Url::parse(url).ok()?;
        let mut t = u.path().to_string();
        if let Some(q) = u.query() {
            t.push('?');
            t.push_str(q);
        }
        Some(t)
    };
    for url in [
        "https://vendor.example",
        "https://vendor.example/",
        "https://vendor.example?x=1",
        "https://agent.example/a2a",
        "http://agent.example/a2a/v1?tenant=t1&x=a%20b",
        "https://agent.example//double/slash",
        "https://Agent.Example/Path/Case",
        "https://agent.example/a/./b",
        "https://agent.example/a/../b",
        "https://agent.example/a/%2E%2E/b",
        "https://agent.example/a b",
        "https://agent.example/a#frag",
        "https://agent.example:8443/a",
        "https://user@agent.example/a",
        "https://10.0.0.1/a",
        "https://1.2.3.999/a",
        "https://[::1]/a",
        "https://agent.example/ü",
        "https://agent.example/q?a='b'",
        "not a url",
    ] {
        assert_eq!(target_of(url), parsed(url), "{url}");
    }
}

#[test]
fn an_attempt_at_an_agent_the_section_does_not_name_is_refused() {
    let mut r = HopRelay::new(json!(7), "0.3");
    assert_eq!(r.on_piece(kernel(None)), PieceAnswer::Refused);
}

#[test]
fn the_callers_body_reaches_the_far_end_verbatim() {
    let odd = br#"{ "jsonrpc" : "2.0", "id":7, "method":"GetExtendedAgentCard", "x":[1,2] }"#;
    let mut r = HopRelay::new(json!(7), "0.3");
    let _ = r.on_piece(kernel(Some(URL)));
    assert_eq!(r.on_piece(caller(odd)), PieceAnswer::ToFarEndLent);
}

#[test]
fn a_correlated_result_is_relayed_whole_under_the_callers_id() {
    let mut r = sent();
    assert_eq!(
        r.on_piece(far(Some(200), br#"{"jsonrpc":"2.0","id":7,"#, false)),
        PieceAnswer::Nothing
    );
    let reply = match r.on_piece(far(
        None,
        br#""result":{"name":"Vendor","skills":[]}}"#,
        true,
    )) {
        PieceAnswer::ToCaller(reply) => reply,
        other => panic!("no answer: {other:?}"),
    };
    assert_eq!(reply.status, 200);
    assert_eq!(reply.content_type, "application/json");

    assert_eq!(
        reply.body,
        br#"{"jsonrpc":"2.0","id":7,"result":{"name":"Vendor","skills":[]}}"#.to_vec()
    );
    assert!(r.answered);
    assert_eq!(r.on_piece(far(None, b"late", true)), PieceAnswer::Nothing);
}

#[test]
fn a_status_outside_2xx_is_the_engines_backend_status_refusal() {
    let reply = answered(&mut sent(), 404, br#"{"jsonrpc":"2.0","id":7,"result":{}}"#);
    assert_eq!(reply.status, 502);
    assert_eq!(
        reply.body,
        refused(
            "a2a.hop.backend_status",
            "this agent's backend refused busbar's request"
        )
    );
}

#[test]
fn an_answer_to_another_request_is_refused_not_relayed() {
    let reply = answered(
        &mut sent(),
        200,
        br#"{"jsonrpc":"2.0","id":8,"result":{"s":1}}"#,
    );
    assert_eq!(
        reply.body,
        refused(
            "a2a.hop.reply_uncorrelated",
            "this agent's backend answered something busbar cannot correlate to the request it \
             sent, so it is refused rather than relayed"
        )
    );
}

#[test]
fn the_backends_own_error_is_refused_without_its_words() {
    let reply = answered(
        &mut sent(),
        200,
        br#"{"jsonrpc":"2.0","id":7,"error":{"code":-32001,"message":"internal host db.vendor"}}"#,
    );
    assert_eq!(reply.status, 404);
    assert_eq!(body(&reply)["error"]["code"], -32001);
    assert_eq!(body(&reply)["error"]["data"][0]["reason"], "TASK_NOT_FOUND");
    assert!(!String::from_utf8_lossy(&reply.body).contains("db.vendor"));
}

#[test]
fn a_reply_that_is_not_a_json_rpc_answer_is_refused() {
    let sentence = "this agent's backend replied with something that is not a JSON-RPC answer";
    for body in [&b"<html>"[..], br#"{"id":7,"result":{}}"#] {
        let reply = answered(&mut sent(), 200, body);
        assert_eq!(reply.body, refused("a2a.hop.reply_not_json", sentence));
    }
}

/// A REDIRECTING RELAY PEER IS A FAILURE, NEVER FOLLOWED (docs/security.md: no surface follows
/// an upstream's redirect): every 3xx the agent answers a relayed hop with is the backend-
/// status refusal, its `Location` named nowhere in the caller's answer, and the relay asks for
/// no second attempt at it.
#[test]
fn a_redirecting_relay_peer_is_a_failure() {
    for status in [301, 302, 303, 307, 308] {
        let mut r = sent();
        let reply = answered(&mut r, status, b"");
        assert_eq!(reply.status, 502, "{status}");
        assert_eq!(
            reply.body,
            refused(
                "a2a.hop.backend_status",
                "this agent's backend refused busbar's request"
            ),
            "{status}"
        );
        assert!(
            !String::from_utf8_lossy(&reply.body).contains("elsewhere.example"),
            "{status}: the redirect's target is named nowhere"
        );
        assert!(
            !matches!(
                r.on_piece(kernel(Some("https://elsewhere.example/a2a"))),
                PieceAnswer::Attempt(_)
            ),
            "{status}: an answered hop makes no second attempt"
        );
    }
}

#[test]
fn a_reply_over_the_ceiling_is_refused_and_a_refused_status_is_judged_first() {
    let mut big = br#"{"jsonrpc":"2.0","id":7,"result":""#.to_vec();
    big.resize(MAX_REPLY_BYTES + 10, b'a');
    let reply = answered(&mut sent(), 200, &big);
    assert_eq!(
        reply.body,
        refused(
            "a2a.hop.reply_too_large",
            "this agent's backend replied with more than the fixed reply limit"
        )
    );
    let reply = answered(&mut sent(), 500, &big);
    assert_eq!(
        reply.body,
        refused(
            "a2a.hop.backend_status",
            "this agent's backend refused busbar's request"
        )
    );
}

#[test]
fn the_bytes_moved_count_both_ways_once_the_far_end_answers() {
    let mut r = sent();
    assert_eq!(r.moved(), 0, "nothing was exchanged yet");
    let body = br#"{"jsonrpc":"2.0","id":7,"result":{}}"#;
    let _ = answered(&mut r, 200, body);
    assert_eq!(r.moved(), (ASK.len() + body.len()) as u64);
}

#[test]
fn a_new_attempt_forgets_the_previous_far_end() {
    let mut r = sent();
    let _ = r.on_piece(far(Some(200), br#"{"jsonrpc":"2.0","#, false));
    assert!(matches!(
        r.on_piece(kernel(Some(URL))),
        PieceAnswer::Attempt(_)
    ));
    let _ = r.on_piece(caller(ASK));
    assert_eq!(r.moved(), 0);
    let reply = answered(&mut r, 200, br#"{"jsonrpc":"2.0","id":7,"result":1}"#);
    assert_eq!(reply.status, 200);
}

#[test]
fn a_last_far_end_piece_with_no_status_is_refused() {
    let mut r = sent();
    assert_eq!(r.on_piece(far(None, b"{}", true)), PieceAnswer::Refused);
}

/// An answer closes once, an empty envelope never closes, and a stream closes at its last frame.
#[test]
fn p_item_unary_empty_terminality_an_answer_closes_once_an_empty_envelope_never_and_a_stream_at_its_last_frame(
) {
    let task_answer = br#"{"jsonrpc":"2.0","id":7,"result":{"kind":"task","id":"far-1","status":{"state":"completed"}}}"#;
    let mut r = task_sent(false);
    let reply = answered(&mut r, 200, task_answer);
    assert_eq!(reply.status, 200);
    assert_eq!(body(&reply)["result"]["kind"], "task");
    assert!(r.answered, "a unary Task answer closes its unit");
    assert_eq!(r.take_reading(), Some(Reading::Healthy));
    assert_eq!(
        r.take_settled(),
        vec![TaskSettled::Reported {
            state: TaskState::Completed,
            backend_id: Some("far-1".into()),
        }]
    );
    assert_eq!(
        r.on_piece(far(None, task_answer, true)),
        PieceAnswer::Nothing,
        "and closes it exactly once"
    );
    assert_eq!(r.take_settled(), Vec::new(), "nothing settles twice");

    let message = br#"{"jsonrpc":"2.0","id":7,"result":{"kind":"message","messageId":"m-1"}}"#;
    let mut r = sent();
    let reply = answered(&mut r, 200, message);
    assert_eq!(body(&reply)["result"]["kind"], "message");
    assert!(r.answered, "a unary Message answer closes its unit");
    assert_eq!(r.take_reading(), Some(Reading::Healthy));
    assert_eq!(r.on_piece(far(None, message, true)), PieceAnswer::Nothing);

    let error = br#"{"jsonrpc":"2.0","id":7,"error":{"code":-32001,"message":"no"}}"#;
    let mut r = sent();
    let reply = answered(&mut r, 200, error);
    assert!(body(&reply).get("result").is_none());
    assert!(body(&reply).get("error").is_some());
    assert!(r.answered, "an error answer is terminal");
    assert_eq!(r.take_reading(), Some(Reading::Healthy));
    assert_eq!(r.on_piece(far(None, error, true)), PieceAnswer::Nothing);

    let empty = br#"{"jsonrpc":"2.0","id":7}"#;
    let mut r = sent();
    let reply = answered(&mut r, 200, empty);
    assert_eq!(
        reply.body,
        refused(
            "a2a.hop.reply_not_json",
            "this agent's backend replied with something that is not a JSON-RPC answer"
        )
    );
    assert_eq!(r.take_reading(), Some(Reading::Transient));
    let mut r = task_sent(false);
    let reply = answered(&mut r, 200, empty);
    assert_eq!(reply.status, 502);
    assert!(body(&reply).get("result").is_none());
    assert!(
        !r.take_settled()
            .iter()
            .any(|s| matches!(s, TaskSettled::Reported { .. })),
        "an empty envelope is never the task's answer"
    );
    assert_eq!(r.take_reading(), Some(Reading::Transient));

    let (mut r, _) = events_sent();
    let initial = event(json!({ "kind": "task", "id": "far-1", "contextId": "far-c",
        "status": { "state": "submitted" } }));
    let first = part(r.on_piece(far(Some(200), &initial, false)));
    assert!(
        first.head && !first.last,
        "a streamed initial Task is not the end"
    );
    assert!(!r.answered);
    let update = event(json!({ "kind": "status-update", "taskId": "far-1",
        "status": { "state": "working" }, "final": false }));
    let middle = part(r.on_piece(far(None, &update, false)));
    assert!(
        !middle.head && !middle.last,
        "an intermediate update is not the end"
    );
    assert!(!r.answered);
    let last = event(json!({ "kind": "status-update", "taskId": "far-1",
        "status": { "state": "completed" }, "final": true }));
    let end = part(r.on_piece(far(None, &last, true)));
    assert!(end.last, "the final frame ends the stream");
    assert!(r.answered);
    assert_eq!(
        r.on_piece(far(None, &last, true)),
        PieceAnswer::Nothing,
        "and it ends once"
    );
}

const SEND: &[u8] = br#"{"jsonrpc":"2.0","id":7,"method":"SendMessage","params":{}}"#;

fn task(addressed: bool) -> TaskHop {
    TaskHop {
        task_id: "a2a-p-0102030405060708".into(),
        context_id: "ctx-1".into(),
        addressed,
        skill: None,
        references: Vec::new(),
    }
}

/// A task hop through its attempt and the caller's body, waiting on the far end.
fn task_sent(addressed: bool) -> HopRelay {
    let mut r = HopRelay::new(json!(7), "1.0");
    r.for_task(task(addressed));
    assert!(matches!(
        r.on_piece(kernel(Some(URL))),
        PieceAnswer::Attempt(_)
    ));
    assert_eq!(r.on_piece(caller(SEND)), PieceAnswer::ToFarEndLent);
    r
}

pub(super) fn body(reply: &RelayReply) -> serde_json::Value {
    serde_json::from_slice(&reply.body).expect("json")
}

#[test]
fn a_task_hops_answer_leaves_under_busbars_identity_and_says_what_the_far_end_reported() {
    let mut r = task_sent(false);
    let far = br#"{"jsonrpc":"2.0","id":7,"result":{"kind":"task","id":"far-1","contextId":"far-c","status":{"state":"completed"}}}"#;
    let reply = answered(&mut r, 200, far);
    assert_eq!(reply.status, 200);
    assert_eq!(
        body(&reply),
        json!({ "jsonrpc": "2.0", "id": 7, "result": { "kind": "task",
            "id": "a2a-p-0102030405060708", "contextId": "ctx-1",
            "status": { "state": "completed" } } })
    );
    assert_eq!(
        r.take_settled(),
        vec![TaskSettled::Reported {
            state: TaskState::Completed,
            backend_id: Some("far-1".into()),
        }]
    );
    assert_eq!(r.take_settled(), Vec::new());
}

/// The engine's task-hop refusal body: `code`, `message`, its `ErrorInfo` when A2A defines the
/// code, and the task's `ResourceInfo`.
fn about(code: i64, reason: &str, message: &str) -> serde_json::Value {
    json!({ "jsonrpc": "2.0", "id": 7, "error": { "code": code, "message": message,
        "data": [
            { "@type": "type.googleapis.com/google.rpc.ErrorInfo",
              "domain": "a2a-protocol.org", "reason": reason },
            { "@type": "type.googleapis.com/google.rpc.ResourceInfo",
              "resourceType": "a2a.busbar/task", "resourceName": "a2a-p-0102030405060708" },
        ] } })
}

#[test]
fn a_failed_hop_ends_the_task_it_opened_and_names_it() {
    let mut r = task_sent(false);
    let reply = answered(&mut r, 500, b"oops");
    assert_eq!(reply.status, 502);
    assert_eq!(
        body(&reply),
        about(
            -32006,
            "INVALID_AGENT_RESPONSE",
            "the backend agent did not complete this task"
        )
    );
    assert_eq!(r.take_settled(), vec![TaskSettled::Failed]);
}

#[test]
fn the_far_ends_own_a2a_error_code_travels_and_its_prose_does_not() {
    let mut r = task_sent(false);
    let far =
        br#"{"jsonrpc":"2.0","id":7,"error":{"code":-32001,"message":"secret backend words"}}"#;
    let reply = answered(&mut r, 200, far);
    assert_eq!(reply.status, 404);
    assert_eq!(
        body(&reply),
        about(
            -32001,
            "TASK_NOT_FOUND",
            "the backend agent refused this task"
        )
    );
    assert_eq!(r.take_settled(), vec![TaskSettled::Failed]);

    let mut r = task_sent(false);
    let far = br#"{"jsonrpc":"2.0","id":7,"error":{"code":-32050,"message":"custom"}}"#;
    let reply = answered(&mut r, 200, far);
    assert_eq!(reply.status, 502);
    assert_eq!(
        body(&reply),
        about(
            -32006,
            "INVALID_AGENT_RESPONSE",
            "the backend agent did not complete this task"
        )
    );
}

#[test]
fn a_failed_hop_about_a_held_task_fails_the_request_never_the_task() {
    let mut r = task_sent(true);
    let far = br#"{"jsonrpc":"2.0","id":7,"error":{"code":-32002,"message":"no"}}"#;
    let reply = answered(&mut r, 200, far);
    assert_eq!(reply.status, 400);
    assert_eq!(
        body(&reply),
        about(
            -32002,
            "TASK_NOT_CANCELABLE",
            "the backend agent refused this request"
        )
    );
    assert_eq!(r.take_settled(), Vec::new());

    let mut r = task_sent(true);
    let reply = answered(&mut r, 503, b"");
    assert_eq!(reply.status, 502);
    assert_eq!(
        body(&reply),
        about(
            -32006,
            "INVALID_AGENT_RESPONSE",
            "the backend agent refused this request"
        )
    );
    assert_eq!(r.take_settled(), Vec::new());
}

#[test]
fn a_translated_request_is_sent_once_per_attempt_in_place_of_the_callers_pieces() {
    let mut r = HopRelay::new(json!(7), "1.0");
    r.for_task(task(true));
    r.send_instead(b"translated".to_vec());
    assert!(matches!(
        r.on_piece(kernel(Some(URL))),
        PieceAnswer::Attempt(_)
    ));
    let first = Piece {
        from: From::Caller,
        bytes: b"part-1",
        status: None,
        last: false,
    };
    assert_eq!(
        r.on_piece(first),
        PieceAnswer::ToFarEnd(b"translated".to_vec().into())
    );
    assert_eq!(r.on_piece(caller(b"part-2")), PieceAnswer::Nothing);
    assert!(matches!(
        r.on_piece(kernel(Some(URL))),
        PieceAnswer::Attempt(_)
    ));
    assert_eq!(
        r.on_piece(caller(b"again")),
        PieceAnswer::ToFarEnd(b"translated".to_vec().into())
    );
}

#[test]
fn a_sensitive_replacement_survives_retry_without_reusing_the_callers_body() {
    let mut relay = HopRelay::new(json!(7), "1.0");
    let original = br#"{"credential":"caller-secret"}"#;
    let replacement = br#"{"credential":"translated-secret"}"#;
    relay.send_instead(replacement.to_vec());
    for _ in 0..2 {
        assert!(matches!(
            relay.on_piece(kernel(Some(URL))),
            PieceAnswer::Attempt(_)
        ));
        assert_eq!(
            relay.on_piece(caller(original)),
            PieceAnswer::ToFarEnd(replacement.to_vec().into()),
            "each attempt sends the complete replacement"
        );
        assert_eq!(
            relay.on_piece(caller(b"later caller piece")),
            PieceAnswer::Nothing,
            "later caller pieces cannot append to a replaced request"
        );
    }
}

#[test]
fn a_partial_sensitive_answer_is_replaced_on_retry_and_a_refusal_does_not_echo_it() {
    let mut relay = sent();
    assert_eq!(
        relay.on_piece(far(
            Some(200),
            br#"{"jsonrpc":"2.0","id":7,"result":"stale-secret"#,
            false
        )),
        PieceAnswer::Nothing
    );
    assert!(matches!(
        relay.on_piece(kernel(Some(URL))),
        PieceAnswer::Attempt(_)
    ));
    assert_eq!(relay.on_piece(caller(ASK)), PieceAnswer::ToFarEndLent);
    let fresh = br#"{"jsonrpc":"2.0","id":7,"result":"fresh-secret"}"#;
    let (first, last) = fresh.split_at(fresh.len() / 2);
    assert_eq!(
        relay.on_piece(far(Some(200), first, false)),
        PieceAnswer::Nothing
    );
    let PieceAnswer::ToCaller(reply) = relay.on_piece(far(None, last, true)) else {
        panic!("the complete retry answers");
    };
    let answer: serde_json::Value = serde_json::from_slice(&reply.body).unwrap();
    assert_eq!(answer["result"], "fresh-secret");
    assert!(!String::from_utf8_lossy(&reply.body).contains("stale-secret"));

    let mut refused = sent();
    let reply = answered(&mut refused, 503, b"upstream-secret");
    assert_eq!(reply.status, 502);
    assert!(!String::from_utf8_lossy(&reply.body).contains("upstream-secret"));
}

const GET: &[u8] = br#"{"jsonrpc":"2.0","id":7,"method":"GetTask","params":{"id":"t1"}}"#;

fn rest_relay(task_hop: Option<TaskHop>) -> HopRelay {
    let mut r = HopRelay::new(json!(7), "1.0");
    if let Some(t) = task_hop {
        r.for_task(t);
    }
    r.bind(
        Binding::HttpJson,
        &serde_json::from_slice::<serde_json::Value>(GET).unwrap(),
    );
    r
}

#[test]
fn an_http_json_attempt_is_the_operations_request_line_and_sends_no_body_for_a_read() {
    let mut r = rest_relay(None);
    assert_eq!(
        r.on_piece(kernel(Some(URL))),
        PieceAnswer::Attempt(Attempt {
            verb: "GET",
            target: "/a2a/v1/tasks/t1?tenant=t1".into(),
            fields: vec![
                ("accept", "application/json".into()),
                ("a2a-version", "1.0".into()),
            ],
        })
    );
    assert_eq!(r.on_piece(caller(GET)), PieceAnswer::Nothing);
    let reply = answered(&mut r, 200, br#"{"id":"t1","status":{"state":"working"}}"#);
    assert_eq!(
        body(&reply),
        json!({ "jsonrpc": "2.0", "id": 7, "result": { "id": "t1", "status": { "state": "working" } } })
    );
}

#[test]
fn an_http_json_answer_that_is_not_json_is_a_bad_reply_and_fails_the_task_it_opened() {
    let mut r = rest_relay(Some(task(false)));
    assert!(matches!(
        r.on_piece(kernel(Some(URL))),
        PieceAnswer::Attempt(_)
    ));
    let reply = answered(&mut r, 200, b"<html>");
    assert_eq!(reply.status, 502);
    assert_eq!(
        body(&reply),
        about(
            -32006,
            "INVALID_AGENT_RESPONSE",
            "the backend agent did not complete this task"
        )
    );
    assert_eq!(r.take_settled(), vec![TaskSettled::Failed]);

    let mut r = rest_relay(None);
    assert!(matches!(
        r.on_piece(kernel(Some(URL))),
        PieceAnswer::Attempt(_)
    ));
    let reply = answered(&mut r, 200, b"<html>");
    assert_eq!(
        body(&reply)["error"]["message"],
        "a2a.hop.reply_not_json: this agent's backend replied with something that is not a JSON-RPC answer"
    );
}

/// A FAILOVER FROM A COMPOSED BINDING TO JSON-RPC SENDS THE JSON-RPC REQUEST: the body an
/// HTTP+JSON (or gRPC) attempt composed is that attempt's alone, so the next member, bound to
/// JSON-RPC, gets the translated envelope, or the caller's own bytes when nothing was translated.
#[test]
fn a_json_rpc_attempt_after_a_composed_one_never_sends_the_composed_body() {
    let envelope: serde_json::Value = serde_json::from_slice(SEND).unwrap();
    let translated = br#"{"jsonrpc":"2.0","id":7,"method":"SendMessage","params":{"t":1}}"#;
    for instead in [Some(&translated[..]), None] {
        let mut r = HopRelay::new(json!(7), "1.0");
        if let Some(body) = instead {
            r.send_instead(body.to_vec());
        }
        r.bind(Binding::HttpJson, &envelope);
        assert!(matches!(
            r.on_piece(kernel(Some(URL))),
            PieceAnswer::Attempt(_)
        ));
        let composed = r.on_piece(caller(SEND));
        assert!(
            matches!(&composed, PieceAnswer::ToFarEnd(body) if !body.starts_with(b"{\"jsonrpc\"")),
            "the HTTP+JSON attempt sends its composed body: {composed:?}"
        );

        r.bind(Binding::JsonRpc, &envelope);
        assert!(matches!(
            r.on_piece(kernel(Some(URL))),
            PieceAnswer::Attempt(_)
        ));
        let expected = match instead {
            Some(body) => PieceAnswer::ToFarEnd(body.to_vec().into()),
            None => PieceAnswer::ToFarEndLent,
        };
        assert_eq!(r.on_piece(caller(SEND)), expected, "{instead:?}");
    }
}

#[test]
fn a_request_the_binding_cannot_carry_is_refused_at_the_attempt() {
    let mut r = HopRelay::new(json!(7), "1.0");
    r.bind(
        Binding::HttpJson,
        &json!({ "jsonrpc": "2.0", "id": 7, "method": "vendor/Thing" }),
    );
    let PieceAnswer::ToCaller(reply) = r.on_piece(kernel(Some(URL))) else {
        panic!("not refused");
    };
    assert_eq!(reply.status, 502);
    assert_eq!(
        body(&reply)["error"]["message"],
        "a2a.hop.unframable: `vendor/Thing` could not be carried to this agent over its `HTTP+JSON` binding"
    );
}

#[test]
fn a_card_naming_only_grpc_is_refused_by_name_before_the_hop() {
    let mut r = HopRelay::new(json!(7), "1.0");
    r.for_task(task(false));
    r.bind(Binding::JsonRpc, &serde_json::from_slice(SEND).unwrap());
    let PieceAnswer::ToCaller(reply) = r.refuse_unspeakable("GRPC") else {
        panic!("not refused");
    };
    assert_eq!(reply.status, 502);
    assert_eq!(
        body(&reply),
        json!({ "jsonrpc": "2.0", "id": 7, "error": { "code": -32006,
            "message": "a2a.hop.unframable: `SendMessage` could not be carried to this agent over its `GRPC` binding",
            "data": [{ "@type": "type.googleapis.com/google.rpc.ErrorInfo",
                "domain": "a2a-protocol.org", "reason": "INVALID_AGENT_RESPONSE" }] } })
    );
    assert_eq!(r.take_settled(), Vec::new(), "the task stays as it is");
    assert_eq!(r.on_piece(caller(SEND)), PieceAnswer::Nothing);
}

const STREAM: &[u8] = br#"{"jsonrpc":"2.0","id":7,"method":"message/stream","params":{}}"#;

/// An events hop about a task, through its attempt and the caller's body.
fn events_sent() -> (HopRelay, Attempt) {
    let mut r = HopRelay::new(json!(7), "1.0");
    r.expect_events();
    r.for_task(task(false));
    let PieceAnswer::Attempt(attempt) = r.on_piece(kernel(Some(URL))) else {
        panic!("no attempt");
    };
    assert_eq!(r.on_piece(caller(STREAM)), PieceAnswer::ToFarEndLent);
    (r, attempt)
}

/// One far-end event answering request 7 with `result`.
fn event(result: serde_json::Value) -> Vec<u8> {
    format!(
        "data: {}\n\n",
        json!({ "jsonrpc": "2.0", "id": 7, "result": result })
    )
    .into_bytes()
}

pub(super) fn part(answer: PieceAnswer) -> Part {
    match answer {
        PieceAnswer::Part(part) => part,
        other => panic!("not a part: {other:?}"),
    }
}

/// The data of each event in `body`.
fn datas(body: &[u8]) -> Vec<serde_json::Value> {
    std::str::from_utf8(body)
        .unwrap()
        .split("\n\n")
        .filter_map(|e| e.strip_prefix("data: "))
        .map(|d| serde_json::from_str(d).unwrap())
        .collect()
}

/// The attempt accepts an event stream or one document (the engine's `ACCEPT_STREAM`).
#[test]
fn an_events_attempt_accepts_an_event_stream_or_one_document() {
    let (_, attempt) = events_sent();
    assert!(attempt
        .fields
        .contains(&(H_ACCEPT, "text/event-stream, application/json".into())));
}

/// Each event goes out as it is framed, under busbar's identity: the first starts the caller's
/// answer, the last piece ends it, and every state the events report is settled as it passes.
#[test]
fn events_are_answered_as_they_come_and_settled_as_they_pass() {
    let (mut r, _) = events_sent();
    let first = event(
        json!({ "kind": "status-update", "taskId": "far-1", "contextId": "far-c",
        "status": { "state": "working" } }),
    );
    let (head, tail) = first.split_at(10);
    assert_eq!(
        r.on_piece(far(Some(200), head, false)),
        PieceAnswer::Nothing,
        "half an event"
    );
    let one = part(r.on_piece(far(None, tail, false)));
    assert!(one.head && !one.last);
    let got = datas(&one.body);
    assert_eq!(got.len(), 1);
    assert_eq!(got[0]["result"]["taskId"], "a2a-p-0102030405060708");
    assert_eq!(got[0]["result"]["contextId"], "ctx-1");
    assert_eq!(
        r.take_settled(),
        vec![TaskSettled::Event {
            state: Some(TaskState::Working),
            artifact: false,
            backend_id: Some("far-1".into()),
        }]
    );
    let mut rest = event(json!({ "artifactUpdate": { "taskId": "far-1", "artifact": {} } }));
    rest.extend(event(json!({ "statusUpdate": { "taskId": "far-1",
        "status": { "state": "completed" } } })));
    let two = part(r.on_piece(far(None, &rest, true)));
    assert!(!two.head && two.last);
    assert_eq!(datas(&two.body).len(), 2);
    assert_eq!(
        r.take_settled(),
        vec![
            TaskSettled::Event {
                state: None,
                artifact: true,
                backend_id: Some("far-1".into()),
            },
            TaskSettled::Event {
                state: Some(TaskState::Completed),
                artifact: false,
                backend_id: Some("far-1".into()),
            },
        ]
    );
    assert!(r.answered);
    assert_eq!(r.moved(), (STREAM.len() + first.len() + rest.len()) as u64);
}

/// AN ERROR FRAME MID-STREAM PASSES THROUGH AND THE STREAM ENDS WHERE THE FAR END CLOSES IT
/// (coordinator ruling, parity principle: "do exactly what v1.5.5 did"). v1.5.5 had no A2A
/// stream to relay one on: its tree holds no a2a crate or module (`git ls-tree -r --name-only
/// v1.5.5` names no path matching `a2a`), no JSON-RPC reader (`git grep -il jsonrpc v1.5.5`
/// matches no file), and names A2A only as work to come (v1.5.5 `qa/segments.toml:61` "a2a ->
/// 1.5.6" and `:169-172`, the `a2a` segment `status = "reserved"`;
/// `crates/busbar/src/config/named_map.rs:16`, "`agents:` (1.5.6 A2A)").
#[test]
fn an_error_frame_mid_stream_passes_through_and_the_stream_ends_where_the_far_end_closes() {
    let (mut r, _) = events_sent();
    let working = event(json!({ "kind": "status-update", "taskId": "far-1",
        "status": { "state": "working" }, "final": false }));
    let first = part(r.on_piece(far(Some(200), &working, false)));
    assert!(first.head && !first.last, "the answer starts");
    let _ = r.take_settled();

    let error = format!(
        "data: {}\n\n",
        json!({ "jsonrpc": "2.0", "id": 7,
            "error": { "code": -32603, "message": "far end broke" } })
    )
    .into_bytes();
    let middle = part(r.on_piece(far(None, &error, false)));
    assert!(
        !middle.head && !middle.last,
        "the error frame neither starts nor ends the answer"
    );
    let got = datas(&middle.body);
    assert_eq!(got.len(), 1, "the error frame goes out as one event");
    assert_eq!(got[0]["id"], 7, "under the caller's id");
    assert_eq!(got[0]["error"]["code"], -32603);
    assert_eq!(
        got[0]["error"]["message"],
        crate::events::BACKEND_ERROR_TEXT,
        "the far end's prose never travels"
    );
    assert!(!String::from_utf8_lossy(&middle.body).contains("far end broke"));
    assert!(got[0].get("result").is_none());
    assert!(!r.answered, "the stream goes on after the error frame");
    assert_eq!(
        r.take_settled(),
        Vec::new(),
        "the error frame settles nothing about the task"
    );

    let after = event(json!({ "kind": "status-update", "taskId": "far-1",
        "status": { "state": "completed" }, "final": true }));
    let end = part(r.on_piece(far(None, &after, true)));
    assert!(end.last, "the answer ends on the far end's last piece");
    assert_eq!(
        datas(&end.body).len(),
        1,
        "the frame after the error passes too"
    );
    assert!(r.answered);
    assert_eq!(
        r.on_piece(far(None, &after, true)),
        PieceAnswer::Nothing,
        "and it ends once"
    );
}

/// A far end that answers one document to an events hop is answered as the unary hop answers it.
#[test]
fn one_document_to_an_events_hop_is_the_unary_answer() {
    let (mut r, _) = events_sent();
    let doc = br#"{"jsonrpc":"2.0","id":7,"result":{"kind":"task","id":"far-1","status":{"state":"completed"}}}"#;
    let reply = answered(&mut r, 200, doc);
    assert_eq!(reply.content_type, "application/json");
    assert_eq!(body(&reply)["result"]["id"], "a2a-p-0102030405060708");
    assert_eq!(
        r.take_settled(),
        vec![TaskSettled::Reported {
            state: TaskState::Completed,
            backend_id: Some("far-1".into()),
        }]
    );
}

/// A frame answering another request refuses the hop before its answer started, the task
/// failed; after it started, the answer ends there and the task fails.
#[test]
fn an_uncorrelated_event_refuses_before_the_answer_and_ends_it_after() {
    let other = b"data: {\"jsonrpc\":\"2.0\",\"id\":99,\"result\":{}}\n\n";
    let (mut before, _) = events_sent();
    let reply = answered(&mut before, 200, other);
    assert_eq!(reply.status, 502);
    assert_eq!(before.take_settled(), vec![TaskSettled::Failed]);

    let (mut after, _) = events_sent();
    let first = event(json!({ "kind": "status-update", "status": { "state": "working" } }));
    assert!(part(after.on_piece(far(Some(200), &first, false))).head);
    let _ = after.take_settled();
    let end = part(after.on_piece(far(None, other, false)));
    assert!(end.last && !end.head && end.body.is_empty());
    assert_eq!(after.take_settled(), vec![TaskSettled::Failed]);
    assert_eq!(
        after.on_piece(far(None, b"", true)),
        PieceAnswer::Nothing,
        "nothing after the end"
    );
}

#[test]
fn malformed_data_fails_the_stream_without_forwarding_backend_bytes() {
    for data in [
        b"data: PRIVATE not json\n\n".as_slice(),
        b"data: {\"id\":\"PRIVATE-backend-id\"}\n\n",
    ] {
        for started in [false, true] {
            let (mut relay, _) = events_sent();
            if started {
                let first = event(json!({"kind":"status-update","status":{"state":"working"}}));
                assert!(!part(relay.on_piece(far(Some(200), &first, false))).last);
                let _ = relay.take_settled();
                let _ = relay.take_reading();
            }
            let answer = relay.on_piece(far(Some(200), data, false));
            if started {
                let end = part(answer);
                assert!(end.last && !end.head && end.body.is_empty());
            } else {
                let PieceAnswer::ToCaller(reply) = answer else {
                    panic!("{answer:?}");
                };
                assert_eq!(reply.status, 502);
                assert!(!String::from_utf8_lossy(&reply.body).contains("PRIVATE"));
            }
            assert_eq!(relay.take_settled(), vec![TaskSettled::Failed]);
            assert_eq!(relay.take_reading(), Some(Reading::Transient));
            assert_eq!(
                relay.on_piece(far(None, b"late", true)),
                PieceAnswer::Nothing
            );
        }
    }
}

/// A status outside 2xx is the unary hop's backend-status refusal, whatever the body.
#[test]
fn an_events_hop_answered_outside_2xx_is_refused() {
    let (mut r, _) = events_sent();
    let reply = answered(&mut r, 503, &event(json!({})));
    assert_eq!(reply.status, 502);
}

/// An HTTP+JSON far end's events carry the bare result: each is read as the result of the request.
#[test]
fn an_http_json_far_ends_bare_events_are_read_as_results() {
    let mut r = HopRelay::new(json!(7), "1.0");
    r.expect_events();
    r.for_task(task(false));
    let envelope: serde_json::Value = serde_json::from_slice(STREAM).unwrap();
    r.bind(Binding::HttpJson, &envelope);
    assert!(matches!(
        r.on_piece(kernel(Some(URL))),
        PieceAnswer::Attempt(_)
    ));
    let _ = r.on_piece(caller(STREAM));
    let bare = b"data: {\"kind\":\"status-update\",\"status\":{\"state\":\"working\"}}\n\n";
    let one = part(r.on_piece(far(Some(200), bare, true)));
    let got = datas(&one.body);
    assert_eq!(got[0]["id"], 7);
    assert_eq!(got[0]["result"]["taskId"], "a2a-p-0102030405060708");
}

/// The plane states the breaker-health classification of the far end's complete answer.
#[test]
fn the_far_ends_whole_answer_states_the_breakers_reading() {
    let not_found =
        br#"{"jsonrpc":"2.0","id":7,"error":{"code":-32001,"message":"Task not found"}}"#;
    let result = br#"{"jsonrpc":"2.0","id":7,"result":{"kind":"message"}}"#;
    let cases: &[(u32, &[u8], Option<Reading>)] = &[
        (200, result, Some(Reading::Healthy)),
        (200, not_found, Some(Reading::Healthy)),
        (502, not_found, Some(Reading::Transient)),
        (500, not_found, Some(Reading::Transient)),
        (529, not_found, Some(Reading::Transient)),
        (408, b"", Some(Reading::Transient)),
        (404, not_found, Some(Reading::Caller)),
        (502, b"SyntaxError: not JSON", Some(Reading::Transient)),
        (503, br#"{"error":"down"}"#, Some(Reading::Transient)),
        (429, b"", Some(Reading::Transient)),
        (401, not_found, Some(Reading::Hard)),
        (403, b"", Some(Reading::Hard)),
        (404, b"no such path", Some(Reading::Caller)),
        (200, b"not json", Some(Reading::Transient)),
        (
            200,
            br#"{"jsonrpc":"2.0","id":8,"result":{}}"#,
            Some(Reading::Transient),
        ),
        (302, b"", Some(Reading::Caller)),
        (302, not_found, Some(Reading::Caller)),
    ];
    for (status, body, want) in cases {
        let mut r = sent();
        assert_eq!(
            r.on_piece(far(Some(*status), &[], false)),
            PieceAnswer::Nothing
        );
        assert_eq!(r.take_reading(), None, "the head alone states nothing");
        let _ = r.on_piece(far(None, body, true));
        assert_eq!(
            r.take_reading(),
            *want,
            "{status} {}",
            String::from_utf8_lossy(body)
        );
        assert_eq!(r.take_reading(), None, "stated once");
    }
}

/// A HOP THE KERNEL REFUSED FOR BUSBAR'S OWN CREDENTIAL (`credential_unavailable`: the agent's
/// `upstream_credential` no longer resolves), in the engine's bytes (`receive.rs`, the
/// `mint_from` arm): a task hop is `fail_task`'s answer, `502` `-32006` "the backend agent did
/// not complete this task" naming the task, and the task ends `failed` — whether the hop opened
/// it or addressed it, as `fail_task` ended either; the extended-card read opened no task, so
/// it is refused in its own words and nothing is settled.
#[test]
fn a_hop_refused_for_busbars_own_credential_answers_in_the_engines_words() {
    for addressed in [false, true] {
        let mut r = task_sent(addressed);
        let (reply, failed) = r.refuse_credential();
        assert_eq!(reply.status, 502);
        assert_eq!(reply.content_type, JSON_MEDIA_TYPE);
        assert_eq!(
            body(&reply),
            about(
                -32006,
                "INVALID_AGENT_RESPONSE",
                "the backend agent did not complete this task"
            ),
            "addressed: {addressed}"
        );
        assert!(failed, "the task ends failed (addressed: {addressed})");
        assert!(r.answered);
    }

    let mut r = sent();
    let (reply, failed) = r.refuse_credential();
    assert_eq!(reply.status, 502);
    assert_eq!(
        body(&reply),
        json!({ "jsonrpc": "2.0", "id": 7, "error": { "code": -32006,
            "message": "the extended agent card could not be fetched",
            "data": [{ "@type": "type.googleapis.com/google.rpc.ErrorInfo",
                "domain": "a2a-protocol.org", "reason": "INVALID_AGENT_RESPONSE" }] } }),
        "no task is named: the card read opened none"
    );
    assert!(!failed, "a card read settles nothing");
    assert!(r.take_settled().is_empty());
}

/// Ported from busbar-a2a a2a/tests/rpcerror_tests.rs::push_notification_not_supported_and_extension_support_required_round_trip.
#[test]
fn a_far_ends_push_and_extension_refusals_are_relayed_as_themselves() {
    for (code, reason) in [
        (-32003, "PUSH_NOTIFICATION_NOT_SUPPORTED"),
        (-32008, "EXTENSION_SUPPORT_REQUIRED"),
    ] {
        for addressed in [false, true] {
            let mut r = task_sent(addressed);
            let far = format!(
                r#"{{"jsonrpc":"2.0","id":7,"error":{{"code":{code},"message":"backend words"}}}}"#
            );
            let reply = answered(&mut r, 200, far.as_bytes());
            assert_eq!(reply.status, 400, "{code} addressed={addressed}");
            let got = body(&reply);
            assert_eq!(got["error"]["code"], code, "relayed code carried through");
            assert_eq!(got["error"]["data"][0]["reason"], reason);
            assert!(
                !reply_text(&reply).contains("backend words"),
                "the far end's prose never travels"
            );
        }
    }
}

fn reply_text(reply: &RelayReply) -> String {
    String::from_utf8_lossy(&reply.body).into_owned()
}

/// Ported from busbar-a2a a2a/tests/transport_tests.rs::a_buffered_hop_that_dies_mid_answer_bills_its_request_and_the_bytes_received.
#[test]
fn a_buffered_hop_that_dies_mid_answer_bills_its_request_and_the_bytes_received() {
    const DELIVERED: usize = 300;
    let mut r = sent();
    let partial = vec![b'x'; DELIVERED];
    assert_eq!(
        r.on_piece(far(Some(200), &partial, false)),
        PieceAnswer::Nothing,
        "the answer is incomplete, so nothing is relayed"
    );

    assert!(!r.answered, "an answer cut short is not an answer");
    assert_eq!(
        r.moved(),
        (ASK.len() + DELIVERED) as u64,
        "the hop bills the request it carried and the bytes that arrived before the reset"
    );
}

/// Ported from busbar-a2a a2a/tests/refusal_leak_tests.rs::every_hop_refusal_carries_its_own_stable_code.
#[test]
fn every_hop_refusal_carries_its_own_stable_code() {
    let arms = [
        HopRefusal::Status,
        HopRefusal::BodyTooLarge,
        HopRefusal::NotJson,
        HopRefusal::BackendError,
        HopRefusal::Uncorrelated,
        HopRefusal::NotServing,
        HopRefusal::EndpointRefused,
        HopRefusal::Transport,
    ];

    for arm in arms {
        match arm {
            HopRefusal::Status
            | HopRefusal::BodyTooLarge
            | HopRefusal::NotJson
            | HopRefusal::BackendError
            | HopRefusal::Uncorrelated
            | HopRefusal::NotServing
            | HopRefusal::EndpointRefused
            | HopRefusal::Transport => {}
        }
    }
    let mut seen: Vec<&'static str> = Vec::new();
    for refusal in arms {
        let code = refusal.client_code();
        assert!(
            code.starts_with("a2a.hop."),
            "{refusal:?} has code `{code}`, outside the plane's `a2a.hop.` family"
        );
        assert!(
            !seen.contains(&code),
            "{refusal:?} reuses the code `{code}`; a code that names two refusals tells an \
             operator nothing"
        );
        assert!(
            refusal.client_text().contains(code),
            "{refusal:?}'s caller-facing text does not carry its own code `{code}`"
        );
        seen.push(code);
    }
    assert_eq!(seen.len(), 8);
}

/// A well-formed far-end answer of exactly `len` bytes.
fn answer_of_len(len: usize) -> Vec<u8> {
    let head = br#"{"jsonrpc":"2.0","id":7,"result":""#;
    let tail = br#""}"#;
    let mut body = head.to_vec();
    body.resize(len - tail.len(), b'a');
    body.extend_from_slice(tail);
    assert_eq!(body.len(), len);
    body
}

/// Ported from busbar-a2a a2a/tests/transport_tests.rs::an_oversized_body_is_cut_one_byte_past_the_ceiling_so_the_driver_can_refuse_it.
#[test]
fn an_oversized_body_is_cut_one_byte_past_the_ceiling_so_the_driver_can_refuse_it() {
    let at_cap = answer_of_len(MAX_REPLY_BYTES);
    let reply = answered(&mut sent(), 200, &at_cap);
    assert_eq!(reply.status, 200, "a body AT the ceiling is not over it");

    let over = answer_of_len(MAX_REPLY_BYTES + 1);
    let reply = answered(&mut sent(), 200, &over);
    assert_eq!(reply.status, 502);
    assert_eq!(
        reply.body,
        refused(
            "a2a.hop.reply_too_large",
            "this agent's backend replied with more than the fixed reply limit"
        )
    );

    let huge = answer_of_len(MAX_REPLY_BYTES * 3);
    let mut r = sent();
    let (a, b) = huge.split_at(MAX_REPLY_BYTES * 2);
    assert_eq!(r.on_piece(far(Some(200), a, false)), PieceAnswer::Nothing);
    assert_eq!(
        r.far.len(),
        MAX_REPLY_BYTES + 1,
        "cut one byte past the cap"
    );
    let reply = match r.on_piece(far(None, b, true)) {
        PieceAnswer::ToCaller(reply) => reply,
        other => panic!("no answer: {other:?}"),
    };
    assert_eq!(
        reply.body,
        refused(
            "a2a.hop.reply_too_large",
            "this agent's backend replied with more than the fixed reply limit"
        )
    );
    assert_eq!(r.far.len(), MAX_REPLY_BYTES + 1);
}

/// What `run` answers the caller, and the lines it journaled.
fn journaled(run: impl FnOnce() -> RelayReply) -> (RelayReply, Vec<(tracing::Level, String)>) {
    let (sent, heard) = std::sync::mpsc::channel();
    let reply = tracing::subscriber::with_default(Capture(sent), run);
    (reply, heard.try_iter().collect())
}

/// Ported from origin/predev `crates/busbar-a2a/src/a2a/tests/refusal_leak_tests.rs`
#[test]
fn a_refused_hops_journal_and_answer_do_not_name_the_backend_endpoint() {
    let host = "vendor.example";
    let submission = crate::diagnostics::A2A_RELAYED_SUBMISSION_FAILED
        .banner()
        .to_string();
    let stream = crate::diagnostics::A2A_RELAYED_STREAM_REFUSED
        .banner()
        .to_string();
    let other = b"data: {\"jsonrpc\":\"2.0\",\"id\":99,\"result\":{}}\n\n";
    type Run = Box<dyn FnOnce() -> RelayReply>;
    let cases: Vec<(&str, String, Run)> = vec![
        (
            "a task-less hop's backend status",
            submission.clone(),
            Box::new(|| answered(&mut sent(), 503, b"{}")),
        ),
        (
            "a task-less hop that heard nothing back",
            submission.clone(),
            Box::new(|| sent().refuse_transport().0),
        ),
        (
            "a task hop's backend status",
            submission.clone(),
            Box::new(|| answered(&mut task_sent(false), 503, b"{}")),
        ),
        (
            "a stream refused after its answer began",
            stream,
            Box::new(move || {
                let (mut r, _) = events_sent();
                let first =
                    event(json!({ "kind": "status-update", "status": { "state": "working" } }));
                let started = part(r.on_piece(far(Some(200), &first, false)));
                assert!(started.head && !started.last && !started.body.is_empty());
                let refused = part(r.on_piece(far(None, other, false)));
                assert!(
                    !refused.head && refused.last,
                    "the refusal ends the caller's stream"
                );
                let mut body = started.body.clone();
                body.extend(refused.body.clone());
                RelayReply {
                    status: 0,
                    content_type: "",
                    body,
                }
            }),
        ),
    ];
    for (what, banner, run) in cases {
        let (reply, lines) = journaled(run);
        let journal = lines
            .iter()
            .find(|(_, line)| line.contains(&banner))
            .unwrap_or_else(|| panic!("{what}: nothing journaled under {banner}: {lines:?}"));
        assert_eq!(journal.0, tracing::Level::DEBUG, "{what}: at debug");
        assert!(
            !journal.1.contains(host),
            "{what}: the operator's line must redact the backend endpoint: {}",
            journal.1
        );
        assert!(
            !String::from_utf8_lossy(&reply.body).contains(host),
            "{what}: the caller's answer names no backend"
        );
    }
}

/// Diagnostics identify the agent without revealing its registered endpoint.
#[test]
fn a_refused_hops_journal_line_omits_the_backend_urls_query() {
    let (_, lines) = journaled(|| answered(&mut sent(), 503, b"{}"));
    let banner = crate::diagnostics::A2A_RELAYED_SUBMISSION_FAILED
        .banner()
        .to_string();
    let (_, line) = lines
        .iter()
        .find(|(_, line)| line.contains(&banner))
        .unwrap_or_else(|| panic!("nothing journaled: {lines:?}"));
    assert!(!line.contains("vendor.example/a2a/v1"), "{line}");
    assert!(!line.contains("tenant=t1"), "{line}");
}

/// AN AGENT URL WITH NO SENDABLE TARGET IS REFUSED LOUDLY: the attempt is refused and the
/// operator's journal says why, as every other refused attempt's does.
#[test]
fn an_agent_url_with_no_target_is_refused_with_a_journal_line() {
    let (_, lines) = journaled(|| {
        let mut r = HopRelay::new(json!(7), "1.0");
        assert_eq!(
            r.on_piece(kernel(Some("https://bad host/a2a"))),
            PieceAnswer::Refused
        );
        RelayReply {
            status: 0,
            content_type: "",
            body: Vec::new(),
        }
    });
    assert!(
        lines
            .iter()
            .any(|(_, line)| line.contains(HopRefusal::EndpointRefused.client_code())),
        "{lines:?}"
    );
}

/// A MESSAGE-ONLY ANSWER SETTLES THE TASK THE HOP OPENED `completed`: a server message names a
/// task only if one was created (A2A v1.0 `Message`, a2a.proto:254-259), so a standalone
/// message is the whole interaction, and busbar's task for it is terminal (and so swept by
/// retention), never left `working`.
#[test]
fn a_message_only_answer_settles_the_opened_task_completed() {
    for far in [
        br#"{"jsonrpc":"2.0","id":7,"result":{"message":{"messageId":"m","role":"ROLE_AGENT","parts":[]}}}"#.as_slice(),
        br#"{"jsonrpc":"2.0","id":7,"result":{"kind":"message","messageId":"m","role":"agent","parts":[]}}"#.as_slice(),
    ] {
        let mut r = task_sent(false);
        let reply = answered(&mut r, 200, far);
        assert_eq!(reply.status, 200);
        assert_eq!(
            r.take_settled(),
            vec![TaskSettled::Reported {
                state: TaskState::Completed,
                backend_id: None,
            }],
            "{}",
            String::from_utf8_lossy(far)
        );
    }
    let in_a_task = br#"{"jsonrpc":"2.0","id":7,"result":{"message":{"messageId":"m","taskId":"far-1","parts":[]}}}"#;
    let mut r = task_sent(false);
    let _ = answered(&mut r, 200, in_a_task);
    assert_eq!(
        r.take_settled(),
        vec![TaskSettled::Reported {
            state: TaskState::Working,
            backend_id: Some("far-1".into()),
        }]
    );
    let alone = br#"{"jsonrpc":"2.0","id":7,"result":{"message":{"messageId":"m","parts":[]}}}"#;
    let mut r = task_sent(true);
    let _ = answered(&mut r, 200, alone);
    assert_eq!(
        r.take_settled(),
        vec![TaskSettled::Reported {
            state: TaskState::Working,
            backend_id: None,
        }],
        "a held task is not closed by a message"
    );

    let (mut r, _) = events_sent();
    let only = event(json!({ "message": { "messageId": "m", "role": "ROLE_AGENT", "parts": [] } }));
    let _ = r.on_piece(far(Some(200), &only, true));
    assert_eq!(
        r.take_settled(),
        vec![TaskSettled::Event {
            state: Some(TaskState::Completed),
            artifact: false,
            backend_id: None,
        }]
    );
}

/// THE FAR END'S RESULT LEAVES AS ITS OWN BYTES, BUSBAR'S IDENTITY SPLICED IN (Law 5: a relay
/// sends the bytes with governed byte-level splices; Q128 a2a M8).
#[test]
fn a_relayed_result_is_the_far_ends_bytes_with_busbars_identity_spliced_in() {
    let mut r = task_sent(false);
    let far = br#"{"jsonrpc":"2.0","id":7,"result":{"status":{"state":"completed"},"id":"far-1","n":123456789012345678901234567890,"big":1e400,"contextId":"far-c","kind":"task"}}"#;
    let reply = answered(&mut r, 200, far);
    assert_eq!(reply.status, 200);
    assert_eq!(
        String::from_utf8(reply.body.clone()).unwrap(),
        r#"{"jsonrpc":"2.0","id":7,"result":{"status":{"state":"completed"},"id":"a2a-p-0102030405060708","n":123456789012345678901234567890,"big":1e400,"contextId":"ctx-1","kind":"task"}}"#
    );

    let mut r = sent();
    let reply = answered(
        &mut r,
        200,
        br#"{"jsonrpc":"2.0","id":7,"result":{"z":1,"a":12345678901234567890123}}"#,
    );
    assert_eq!(
        String::from_utf8(reply.body.clone()).unwrap(),
        r#"{"jsonrpc":"2.0","id":7,"result":{"z":1,"a":12345678901234567890123}}"#
    );
}

/// A RESULT THAT IS NO OBJECT IS NO ANSWER ABOUT A TASK (Law 11: no invented answer): the plane
/// cannot read it and refuses it as it refuses an answer that is not JSON.
#[test]
fn a_task_hops_result_that_is_no_object_is_refused_not_invented() {
    for result in ["\"done\"", "[1]", "7", "null"] {
        let far = format!(r#"{{"jsonrpc":"2.0","id":7,"result":{result}}}"#);
        let mut opened = task_sent(false);
        let reply = answered(&mut opened, 200, far.as_bytes());
        assert_eq!(reply.status, 502, "{result}");
        assert_eq!(body(&reply)["error"]["code"], -32006, "{result}");
        assert!(
            !String::from_utf8_lossy(&reply.body).contains("\"kind\":\"task\""),
            "{result}"
        );
        assert_eq!(opened.take_settled(), vec![TaskSettled::Failed], "{result}");

        let mut held = task_sent(true);
        assert_eq!(answered(&mut held, 200, far.as_bytes()).status, 502);
        assert_eq!(held.take_settled(), Vec::new(), "{result}");
    }
    let (mut r, _) = events_sent();
    let end = r.on_piece(far(Some(200), &event(json!("done")), true));
    let PieceAnswer::ToCaller(reply) = end else {
        panic!("refused before the answer: {end:?}");
    };
    assert_eq!(reply.status, 502);
    assert_eq!(r.take_settled(), vec![TaskSettled::Failed]);
}

#[test]
fn http_json_reply_ceiling_counts_only_the_backend_document() {
    let id = json!("large-caller-correlation".repeat(64));
    let request = json!({"jsonrpc":"2.0", "id":id, "method":"GetExtendedAgentCard"});
    let mut relay = HopRelay::new(id.clone(), "1.0");
    relay.bind(Binding::HttpJson, &request);
    assert!(matches!(
        relay.on_piece(kernel(Some(URL))),
        PieceAnswer::Attempt(_)
    ));
    let _ = relay.on_piece(caller(&serde_json::to_vec(&request).unwrap()));
    let mut wire = b"{}".to_vec();
    wire.resize(MAX_REPLY_BYTES, b' ');
    let reply = answered(&mut relay, 200, &wire);
    assert_eq!(reply.status, 200);
    let reply: Value = serde_json::from_slice(&reply.body).unwrap();
    assert_eq!(reply["id"], id);
    assert_eq!(reply["result"], json!({}));
}

#[test]
fn admission_time_refusals_settle_only_new_tasks() {
    for addressed in [false, true] {
        for unspeakable in [false, true] {
            let mut relay = task_sent(addressed);
            let answer = if unspeakable {
                relay.refuse_unspeakable("unknown")
            } else {
                relay.refuse_demoted()
            };
            let PieceAnswer::ToCaller(reply) = answer else {
                panic!("a refusal answers the caller")
            };
            assert!(String::from_utf8_lossy(&reply.body).contains("a2a-p-0102030405060708"));
            assert_eq!(
                relay.take_settled(),
                if addressed {
                    vec![]
                } else {
                    vec![TaskSettled::Failed]
                }
            );
        }
    }
}

#[test]
fn relay_debug_and_journal_never_expose_registered_url() {
    let mut relay = sent();
    let secret = "https://private-host.example/private-path?credential=private-secret";
    relay.name_backend("registered-agent", secret);
    assert!(!format!("{relay:?}").contains("private-"));
    let (_, lines) = journaled(|| relay.refuse_transport().0);
    assert!(lines.iter().all(|(_, line)| !line.contains("private-")));
}

#[test]
fn ending_a_relay_releases_payloads_but_keeps_billing_and_refusal_facts() {
    use crate::tests::raw_custody_probe::{Probe, SECRET};
    let mut relay = task_sent(false);
    relay.send_shared_instead(SECRET.to_vec().into());
    assert_eq!(relay.replacement_bytes(), Some(SECRET));
    let before = (
        relay.sent,
        relay.far_answered(),
        relay.moved(),
        relay.task().cloned(),
    );
    let probe = Probe::start();
    relay.release_payloads();
    probe.checkpoint();
    assert!(relay.replacement_bytes().is_none());
    assert_eq!(
        (
            relay.sent,
            relay.far_answered(),
            relay.moved(),
            relay.task().cloned()
        ),
        before
    );
}

#[test]
fn raw_serialization_starts_with_amortized_room() {
    let mut raw = RawBytes::default();
    raw.extend_from_slice(b"{");
    let pointer = raw.0.as_ptr();
    for _ in 1..256 {
        raw.extend_from_slice(b" ");
    }
    assert_eq!(raw.0.as_ptr(), pointer);
}

#[test]
fn oversized_grpc_answer_is_not_copied_before_refusal() {
    let mut relay = HopRelay::new(json!(7), "1.0");
    relay.binding = Binding::Grpc;
    relay.far = vec![b'x'; MAX_REPLY_BYTES + 1].into();
    let allocation = relay.far.as_slice().as_ptr();
    let PieceAnswer::ToCaller(reply) = relay.whole(STATUS_OK) else {
        panic!("oversize answer refused")
    };
    assert_eq!(reply.status, STATUS_BAD_GATEWAY);
    assert_eq!(relay.far.as_slice().as_ptr(), allocation);
}

#[test]
fn a_taskless_extended_card_hop_preserves_a_valid_backend_unsupported_error() {
    for status in [200, 400] {
        let reply = answered(
            &mut sent(),
            status,
            br#"{"jsonrpc":"2.0","id":7,"error":{"code":-32004,"message":"PRIVATE backend authority","data":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","domain":"a2a-protocol.org","reason":"UNSUPPORTED_OPERATION"}]}}"#,
        );
        assert_eq!(reply.status, 400);
        let doc = body(&reply);
        assert_eq!(doc["id"], 7);
        assert_eq!(doc["error"]["code"], -32004);
        assert_eq!(doc["error"]["data"][0]["reason"], "UNSUPPORTED_OPERATION");
        assert!(!String::from_utf8_lossy(&reply.body).contains("PRIVATE"));
    }
    for wire in [
        br#"{"jsonrpc":"2.0","id":8,"error":{"code":-32004,"message":"PRIVATE"}}"#.as_slice(),
        br#"{"jsonrpc":"2.0","id":7,"error":{"code":-39999,"message":"PRIVATE"}}"#.as_slice(),
    ] {
        let reply = answered(&mut sent(), 200, wire);
        assert_eq!(body(&reply)["error"]["code"], -32006);
        assert!(!String::from_utf8_lossy(&reply.body).contains("PRIVATE"));
    }
}
