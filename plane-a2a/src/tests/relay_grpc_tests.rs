// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! BUSBAR AS AN A2A CLIENT OVER gRPC (the engine's `client_leg_tests.rs`
//! `grpc_client_issues_*`, ported to the door's hop): what each attempt asks to have sent (the
//! rpc's path, its request message) and the caller's answer read off the grpc transport's
//! pieces (its head, each message length-prefixed, its trailers).

use super::tests::{body, caller, far, kernel, part};
use super::*;
use crate::proto::pb;
use prost::Message as _;
use serde_json::json;

#[path = "relay_grpc_g2_tests.rs"]
mod relay_grpc_g2_tests;

/// The operator's `url:` for the agent: its path is never the rpc's.
const URL: &str = "https://backend.agent.test/a2a";

/// The backend's own task id, which every addressed rpc must name.
const BACKEND: &str = "BACKEND-OWN-TASK-ID";

/// One message in its length-prefixed form, as the grpc transport hands an answer back.
fn framed<M: prost::Message>(message: &M) -> Vec<u8> {
    let body = message.encode_to_vec();
    let mut out = vec![0u8];
    out.extend_from_slice(&u32::try_from(body.len()).expect("small").to_be_bytes());
    out.extend_from_slice(&body);
    out
}

fn task(state: pb::TaskState) -> pb::Task {
    crate::proto::custody::initialized::<pb::Task>(|__custody_message| {
        __custody_message.id = BACKEND.into();
        __custody_message.context_id = "BACKEND-OWN-CONTEXT".into();
        __custody_message.status = Some(crate::proto::custody::initialized::<pb::TaskStatus>(
            |__custody_message| {
                __custody_message.state = state as i32;
            },
        ));
    })
}

fn send_answer(state: pb::TaskState) -> Vec<u8> {
    framed(&pb::SendMessageResponse {
        payload: Some(pb::send_message_response::Payload::Task(task(state))),
    })
}

fn stream_event(state: pb::TaskState) -> Vec<u8> {
    framed(&pb::StreamResponse {
        payload: Some(pb::stream_response::Payload::Task(task(state))),
    })
}

/// The v1.0 submission a caller reaching a gRPC agent sends: its params ARE the request
/// message's ProtoJSON.
fn submission(method: &str) -> serde_json::Value {
    json!({
        "jsonrpc": "2.0", "id": 7, "method": method,
        "params": { "message": { "messageId": "m-1", "role": "ROLE_USER",
                                 "parts": [{ "text": "PLAN THE MIGRATION" }] } }
    })
}

/// A hop bound to the gRPC binding for `envelope` (`translated`: the envelope with the far
/// end's own task id, as the door hands it over), through its attempt and the caller's body:
/// the request and the message it sends.
fn dialled(
    envelope: &serde_json::Value,
    translated: Option<&serde_json::Value>,
    events: bool,
) -> (HopRelay, Attempt, Vec<u8>) {
    let mut r = HopRelay::new(json!(7), "1.0");
    if events {
        r.expect_events();
    }
    if let Some(t) = translated {
        r.send_instead(serde_json::to_vec(t).expect("json"));
    }
    r.bind(Binding::Grpc, envelope);
    let PieceAnswer::Attempt(attempt) = r.on_piece(kernel(Some(URL))) else {
        panic!("no attempt on the gRPC binding");
    };
    let bytes = serde_json::to_vec(envelope).expect("json");

    let message = match r.on_piece(caller(&bytes)) {
        PieceAnswer::ToFarEnd(message) => message.into_vec(),
        PieceAnswer::Nothing => Vec::new(),
        other => panic!("no message for the far end: {other:?}"),
    };
    (r, attempt, message)
}

/// The far end's answer, piece by piece as the grpc transport hands it: its head (no status of
/// its own: `0`), `messages`, its trailers (stating `code`), then the end.
fn answer(r: &mut HopRelay, messages: &[Vec<u8>], code: Option<u32>) -> Vec<PieceAnswer> {
    let mut answers = vec![r.on_piece(far(Some(0), &[], false))];
    for m in messages {
        answers.push(r.on_piece(far(None, m, false)));
    }
    answers.push(r.on_far_fields(&[], code, false));
    answers.push(r.on_piece(far(None, &[], true)));
    answers
}

fn whole(answers: Vec<PieceAnswer>) -> RelayReply {
    answers
        .into_iter()
        .find_map(|a| match a {
            PieceAnswer::ToCaller(reply) => Some(reply),
            _ => None,
        })
        .expect("the caller is answered")
}

/// `grpc_client_issues_send_message`: the rpc's own path under the service (never the
/// operator's path), a POST, the gRPC media type, and the caller's content surviving the
/// transcode into the request message; the far end's message reaches the caller as the JSON-RPC
/// result it is.
#[test]
fn grpc_client_issues_send_message() {
    let (mut r, attempt, message) = dialled(&submission("SendMessage"), None, false);
    assert_eq!(attempt.verb, "POST");
    assert_eq!(attempt.target, "/lf.a2a.v1.A2AService/SendMessage");
    assert_eq!(
        attempt.fields,
        vec![
            ("content-type", "application/grpc+proto".into()),
            ("accept", "application/grpc+proto".into()),
            ("a2a-version", "1.0".into()),
        ]
    );
    let req = pb::SendMessageRequest::decode(message.as_slice())
        .expect("the message decodes as the rpc's request");
    assert!(
        format!("{:?}", req.message).contains("PLAN THE MIGRATION"),
        "the caller's own content must survive the transcode"
    );
    let reply = whole(answer(
        &mut r,
        &[send_answer(pb::TaskState::Completed)],
        Some(0),
    ));
    assert_eq!(reply.status, 200);
    let got = body(&reply);
    assert_eq!(got["id"], 7);
    assert_eq!(got["result"]["task"]["id"], BACKEND);
    assert_eq!(
        got["result"]["task"]["status"]["state"],
        "TASK_STATE_COMPLETED"
    );
}

/// A task hop's answer leaves under busbar's identity and settles the task on what the far end
/// reported, as on the other bindings.
#[test]
fn a_grpc_answer_about_a_task_leaves_under_busbars_identity() {
    let (mut r, _, _) = dialled(&submission("SendMessage"), None, false);
    r.for_task(TaskHop {
        task_id: "busbar-t".into(),
        context_id: "busbar-c".into(),
        addressed: false,
        skill: None,
        references: Vec::new(),
    });
    let reply = whole(answer(
        &mut r,
        &[send_answer(pb::TaskState::Completed)],
        Some(0),
    ));
    assert_eq!(body(&reply)["result"]["task"]["id"], "busbar-t");
    assert_eq!(
        r.take_settled(),
        vec![TaskSettled::Reported {
            state: TaskState::Completed,
            backend_id: Some(BACKEND.into()),
        }]
    );
}

/// `grpc_client_issues_get_task`: the rpc names the BACKEND's own task id, not busbar's.
#[test]
fn grpc_client_issues_get_task() {
    let asked =
        json!({ "jsonrpc": "2.0", "id": 7, "method": "GetTask", "params": { "id": "busbar-t" } });
    let translated =
        json!({ "jsonrpc": "2.0", "id": 7, "method": "GetTask", "params": { "id": BACKEND } });
    let (mut r, attempt, message) = dialled(&asked, Some(&translated), false);
    assert_eq!(attempt.target, "/lf.a2a.v1.A2AService/GetTask");
    let req = pb::GetTaskRequest::decode(message.as_slice()).expect("a GetTaskRequest");
    assert_eq!(
        req.id, BACKEND,
        "the rpc must name the BACKEND's own task id, not busbar's"
    );
    let reply = whole(answer(
        &mut r,
        &[framed(&task(pb::TaskState::Completed))],
        Some(0),
    ));
    assert_eq!(body(&reply)["result"]["id"], BACKEND);
}

/// `grpc_client_issues_cancel_task`.
#[test]
fn grpc_client_issues_cancel_task() {
    let asked = json!({ "jsonrpc": "2.0", "id": 7, "method": "tasks/cancel", "params": { "id": "busbar-t" } });
    let translated =
        json!({ "jsonrpc": "2.0", "id": 7, "method": "tasks/cancel", "params": { "id": BACKEND } });
    let (_, attempt, message) = dialled(&asked, Some(&translated), false);
    assert_eq!(attempt.target, "/lf.a2a.v1.A2AService/CancelTask");
    let req = pb::CancelTaskRequest::decode(message.as_slice()).expect("a CancelTaskRequest");
    assert_eq!(req.id, BACKEND);
}

/// `grpc_client_issues_send_stream_message`: the streaming rpc, and each length-prefixed
/// message of its answer reaching the caller as one JSON-RPC response in an event-stream frame.
#[test]
fn grpc_client_issues_send_stream_message() {
    let (mut r, attempt, message) = dialled(&submission("SendStreamingMessage"), None, true);
    assert_eq!(attempt.target, "/lf.a2a.v1.A2AService/SendStreamingMessage");
    let _ = pb::SendMessageRequest::decode(message.as_slice()).expect("a SendMessageRequest");
    let answers = answer(&mut r, &[stream_event(pb::TaskState::Completed)], Some(0));
    let parts: Vec<Part> = answers
        .into_iter()
        .filter_map(|a| match a {
            PieceAnswer::Part(p) => Some(p),
            _ => None,
        })
        .collect();
    assert!(parts[0].head, "the first event starts the caller's stream");
    let sse = String::from_utf8(parts.iter().flat_map(|p| p.body.clone()).collect()).expect("text");
    assert!(sse.starts_with("data: "), "{sse}");
    assert!(
        sse.contains("\"jsonrpc\"") && sse.contains("TASK_STATE_COMPLETED"),
        "a gRPC stream message must reach the caller as a JSON-RPC response: {sse}"
    );
    assert!(parts.last().is_some_and(|p| p.last), "the stream ends");
}

/// A message split across pieces is read once it is whole, and two in one piece are two events.
#[test]
fn a_streamed_message_is_read_once_whole_whatever_the_pieces() {
    let (mut r, _, _) = dialled(&submission("SendStreamingMessage"), None, true);
    let _ = r.on_piece(far(Some(0), &[], false));
    let first = stream_event(pb::TaskState::Working);
    let (a, b) = first.split_at(7);
    assert_eq!(r.on_piece(far(None, a, false)), PieceAnswer::Nothing);
    let PieceAnswer::Part(part) = r.on_piece(far(None, b, false)) else {
        panic!("the whole message is an event");
    };
    assert!(part.head);
    let two = [
        stream_event(pb::TaskState::Working),
        stream_event(pb::TaskState::Completed),
    ]
    .concat();
    let PieceAnswer::Part(part) = r.on_piece(far(None, &two, false)) else {
        panic!("two events");
    };
    assert_eq!(
        String::from_utf8_lossy(&part.body)
            .matches("data: ")
            .count(),
        2
    );
}

/// `grpc_client_issues_subscribe_to_task`: the rpc names the backend's own task id.
#[test]
fn grpc_client_issues_subscribe_to_task() {
    let asked = json!({ "jsonrpc": "2.0", "id": 7, "method": "SubscribeToTask", "params": { "id": "busbar-t" } });
    let translated = json!({ "jsonrpc": "2.0", "id": 7, "method": "SubscribeToTask", "params": { "id": BACKEND } });
    let (mut r, attempt, message) = dialled(&asked, Some(&translated), true);
    assert_eq!(attempt.target, "/lf.a2a.v1.A2AService/SubscribeToTask");
    let req = pb::SubscribeToTaskRequest::decode(message.as_slice()).expect("a subscribe");
    assert_eq!(req.id, BACKEND);
    let answers = answer(&mut r, &[stream_event(pb::TaskState::Working)], Some(0));
    assert!(answers
        .iter()
        .any(|a| matches!(a, PieceAnswer::Part(p) if p.head)));
}

/// `grpc_client_issues_get_extended_agent_card`: a task-less hop; the card the far end answers
/// is the caller's result.
#[test]
fn grpc_client_issues_get_extended_agent_card() {
    let asked =
        json!({ "jsonrpc": "2.0", "id": 7, "method": "GetExtendedAgentCard", "params": {} });
    let (mut r, attempt, message) = dialled(&asked, None, false);
    assert_eq!(attempt.target, "/lf.a2a.v1.A2AService/GetExtendedAgentCard");
    let _ = pb::GetExtendedAgentCardRequest::decode(message.as_slice()).expect("the request");
    let card = framed(&crate::proto::custody::initialized::<pb::AgentCard>(
        |__custody_message| {
            __custody_message.name = "planner-extended".into();
        },
    ));
    let reply = whole(answer(&mut r, &[card], Some(0)));
    assert_eq!(body(&reply)["result"]["name"], "planner-extended");
}

/// THE STATUS THE TRAILERS STATE IS READ: a call that ends with an error is the backend
/// refusing the request (its A2A code where the status binds one, the task's own refusal on a
/// task hop), never a reply busbar cannot read.
#[test]
fn a_grpc_error_status_is_the_backends_refusal_with_its_a2a_code() {
    let asked =
        json!({ "jsonrpc": "2.0", "id": 7, "method": "GetTask", "params": { "id": BACKEND } });
    let (mut r, _, _) = dialled(&asked, None, false);
    r.for_task(TaskHop {
        task_id: "busbar-t".into(),
        context_id: "busbar-c".into(),
        addressed: true,
        skill: None,
        references: Vec::new(),
    });
    let reply = whole(answer(&mut r, &[], Some(5)));
    let got = body(&reply);
    assert_eq!(
        got["error"]["code"], -32001,
        "NOT_FOUND is TaskNotFound: {got}"
    );
    assert_eq!(reply.status, 404);
    assert!(
        r.take_settled().is_empty(),
        "an addressed task is never failed"
    );

    let asked =
        json!({ "jsonrpc": "2.0", "id": 7, "method": "GetExtendedAgentCard", "params": {} });
    let (mut r, _, _) = dialled(&asked, None, false);
    let reply = whole(answer(&mut r, &[], Some(13)));
    assert_eq!(reply.status, 500);
    assert_eq!(
        serde_json::from_slice::<Value>(&reply.body).unwrap(),
        json!({"jsonrpc":"2.0","id":7,"error":{"code":-32603,"message":"this agent's backend refused the request"}})
    );
}

/// A gRPC agent refusing busbar at the HTTP layer (`401`/`403`, no gRPC answer) refuses busbar
/// itself, as on every binding (predev `relay.rs:1583`: `RelayRefusal::Status`, read by the one
/// status table, an auth status hard): the hop's reading is hard, so the kernel takes the
/// member out of its pool's walk.
#[test]
fn a_grpc_agent_refusing_busbar_at_the_http_layer_reads_hard() {
    let asked = submission("SendMessage");
    for status in [401, 403] {
        let (mut r, _, _) = dialled(&asked, None, false);
        let reply = whole(vec![r.on_piece(far(Some(status), b"denied", true))]);
        assert_eq!(reply.status, 502, "status {status}");
        assert_eq!(r.take_reading(), Some(Reading::Hard), "status {status}");
    }
}

/// An answer with no message is an unreadable backend reply, not an unframable caller request.
#[test]
fn a_grpc_answer_with_no_message_is_refused_by_name() {
    let asked =
        json!({ "jsonrpc": "2.0", "id": 7, "method": "GetExtendedAgentCard", "params": {} });
    let (mut r, _, _) = dialled(&asked, None, false);
    let reply = whole(answer(&mut r, &[], None));
    assert_eq!(reply.status, 502);
    assert_eq!(
        body(&reply)["error"]["message"],
        "a2a.hop.reply_not_json: this agent's backend replied with something that is not a JSON-RPC answer"
    );
}

/// A request whose params are not the rpc's request message (a v0.3 document) cannot be framed:
#[test]
fn params_that_are_not_the_request_message_are_refused_before_the_hop() {
    let v03 = json!({
        "jsonrpc": "2.0", "id": 7, "method": "message/send",
        "params": { "message": { "kind": "message", "role": "user", "parts": [] } }
    });
    let mut r = HopRelay::new(json!(7), "0.3");
    r.bind(Binding::Grpc, &v03);
    let PieceAnswer::ToCaller(reply) = r.on_piece(kernel(Some(URL))) else {
        panic!("refused before the hop");
    };
    assert_eq!(reply.status, 502);
    assert!(r.answered);
}

/// THE TRAILERS ARE NEVER BYTES OF THE ANSWER: on the JSON-RPC binding a field block after the
/// body is ignored.
#[test]
fn trailers_after_a_json_rpc_answer_are_not_read_as_its_body() {
    let mut r = HopRelay::new(json!(7), "1.0");
    let _ = r.on_piece(kernel(Some(URL)));
    let _ = r.on_piece(caller(br#"{"jsonrpc":"2.0","id":7,"method":"GetTask"}"#));
    let _ = r.on_piece(far(
        Some(200),
        br#"{"jsonrpc":"2.0","id":7,"result":{}}"#,
        false,
    ));
    assert_eq!(
        r.on_far_fields(b"x-trailer: 1\r\n", None, false),
        PieceAnswer::Nothing
    );
    let PieceAnswer::ToCaller(reply) = r.on_piece(far(None, &[], true)) else {
        panic!("the caller is answered");
    };
    assert_eq!(reply.status, 200);
}

/// THE NEED AN ATTEMPT RIDES: the gRPC binding names the door's gRPC need; the others name none
/// (the member's own).
#[test]
fn a_grpc_attempt_rides_the_doors_grpc_need() {
    use crate::plane_door::attempt_need;
    assert_eq!(attempt_need(Binding::Grpc), crate::statement::NEED_GRPC + 1);
    assert_eq!(attempt_need(Binding::JsonRpc), 0);
    assert_eq!(attempt_need(Binding::HttpJson), 0);
}

/// A final status handed on with the last trailers ends the call.
#[test]
fn a_status_handed_on_with_the_last_trailers_ends_the_call() {
    use crate::framed::{CallStatus, Code, ErrorInfo, DETAILS_FIELD};
    use base64::Engine as _;
    use busbar_contract::abi::transport::fields::{LINE_END, SEPARATOR};
    let asked =
        json!({ "jsonrpc": "2.0", "id": 7, "method": "GetTask", "params": { "id": BACKEND } });
    let hop = || {
        let (mut r, _, _) = dialled(&asked, None, false);
        r.for_task(TaskHop {
            task_id: "busbar-t".into(),
            context_id: "busbar-c".into(),
            addressed: true,
            skill: None,
            references: Vec::new(),
        });
        assert_eq!(r.on_piece(far(Some(0), &[], false)), PieceAnswer::Nothing);
        r
    };
    let answered = |a: PieceAnswer| match a {
        PieceAnswer::ToCaller(reply) => reply,
        other => panic!("the last trailers answer the caller: {other:?}"),
    };

    let mut r = hop();
    let reply = answered(r.on_far_fields(&[], Some(Code::NotFound as u32), true));
    assert_eq!(body(&reply)["error"]["code"], -32001, "{:?}", body(&reply));
    assert_eq!(reply.status, 404);
    assert_eq!(r.take_reading(), Some(Reading::Healthy));

    let mut r = hop();
    let _ = answered(r.on_far_fields(&[], Some(Code::Unauthenticated as u32), true));
    assert_eq!(r.take_reading(), Some(Reading::Hard));

    let details = CallStatus::with_error_info(
        Code::NotFound,
        "no such task",
        ErrorInfo {
            reason: "TASK_NOT_FOUND".into(),
            domain: crate::ERROR_INFO_DOMAIN.into(),
            metadata: std::collections::BTreeMap::new(),
        },
    );
    let mut block = DETAILS_FIELD.as_bytes().to_vec();
    block.extend_from_slice(SEPARATOR);
    block.extend_from_slice(
        base64::engine::general_purpose::STANDARD_NO_PAD
            .encode(details.details())
            .as_bytes(),
    );
    block.extend_from_slice(LINE_END);
    let mut r = hop();
    let reply = answered(r.on_far_fields(&block, None, true));
    assert_eq!(reply.status, 502);
    assert_eq!(body(&reply)["error"]["code"], -32006);
    assert!(body(&reply).get("result").is_none());
    assert_eq!(r.take_reading(), Some(Reading::Transient));
}

/// MONEY (this cell touches money: it reads the count the door reports as the hop's billed
/// `bytes` class, `relay::moved`).
#[test]
fn a_grpc_hop_bills_its_framed_request_and_answer_and_never_its_trailers() {
    use busbar_contract::abi::transport::fields::{LINE_END, SEPARATOR};
    let mut trailers = b"grpc-status".to_vec();
    trailers.extend_from_slice(SEPARATOR);
    trailers.extend_from_slice(b"0");
    trailers.extend_from_slice(LINE_END);
    let billed = |asked: &serde_json::Value, answered: &[u8]| {
        let (mut r, _, message) = dialled(asked, None, false);
        assert_eq!(r.moved(), 0, "nothing was exchanged yet");
        let _ = r.on_piece(far(Some(0), &[], false));
        let _ = r.on_piece(far(None, answered, false));
        let _ = r.on_far_fields(&trailers, Some(0), false);
        let _ = r.on_piece(far(None, &[], true));
        (r.moved(), message.len())
    };
    let answer = send_answer(pb::TaskState::Working);
    let (moved, message) = billed(&submission("SendMessage"), &answer);
    assert!(message > 0, "the submission carries a message");
    assert_eq!(
        moved,
        (crate::framed::MESSAGE_PREFIX + message + answer.len()) as u64,
        "the prefixed request message plus the prefixed answer, and not one trailer byte"
    );

    let card = framed(&crate::proto::custody::initialized::<pb::AgentCard>(
        |__custody_message| {
            __custody_message.name = "planner-extended".into();
        },
    ));
    let asked =
        json!({ "jsonrpc": "2.0", "id": 7, "method": "GetExtendedAgentCard", "params": {} });
    let (moved, message) = billed(&asked, &card);
    assert_eq!(message, 0, "the empty request message");
    assert_eq!(
        moved,
        (crate::framed::MESSAGE_PREFIX + card.len()) as u64,
        "the empty message's prefix plus the prefixed answer"
    );
}

/// An events hop on the gRPC binding about a task it opened, its head read.
fn streaming() -> HopRelay {
    let (mut r, _, _) = dialled(&submission("SendStreamingMessage"), None, true);
    r.for_task(TaskHop {
        task_id: "busbar-t".into(),
        context_id: "busbar-c".into(),
        addressed: false,
        skill: None,
        references: Vec::new(),
    });
    assert_eq!(r.on_piece(far(Some(0), &[], false)), PieceAnswer::Nothing);
    r
}

#[test]
fn a_cut_grpc_stream_ends_with_an_error_even_after_complete_messages() {
    for committed in [false, true] {
        let mut relay = streaming();
        let event = stream_event(pb::TaskState::Working);
        let before = relay.moved();
        let cut = if committed {
            assert!(part(relay.on_piece(far(None, &event, false))).head);
            let _ = relay.take_settled();
            &[][..]
        } else {
            event.as_slice()
        };
        let end = part(relay.on_far_cut(cut, None));
        assert!(end.last);
        assert_eq!(end.head, !committed);
        let error = std::str::from_utf8(&end.body)
            .unwrap()
            .split("\n\n")
            .filter_map(crate::framed::event)
            .find_map(Result::err)
            .expect("a gRPC caller must receive a non-OK final status");
        assert_eq!(error.code(), crate::framed::Code::Internal);
        assert_eq!(relay.take_settled().last(), Some(&TaskSettled::Failed));
        assert_eq!(relay.take_reading(), Some(Reading::Transient));
        assert_eq!(relay.moved(), before + event.len() as u64);
        assert_eq!(
            relay.on_far_fields(&[], Some(0), true),
            PieceAnswer::Nothing
        );
    }
}

/// A gRPC stream ending with an error status fails its task even after events have begun.
#[test]
fn a_grpc_stream_ending_with_an_error_status_fails_its_task() {
    use crate::framed::Code;
    let mut r = streaming();
    let first = part(r.on_piece(far(None, &stream_event(pb::TaskState::Working), false)));
    assert!(first.head && !first.last);
    let _ = r.take_settled();
    assert_eq!(
        r.on_far_fields(&[], Some(Code::NotFound as u32), false),
        PieceAnswer::Nothing
    );
    let end = part(r.on_piece(far(None, &[], true)));
    assert!(end.last && !end.head);
    let text = String::from_utf8(end.body.clone()).unwrap();
    let error: serde_json::Value =
        serde_json::from_str(text.strip_prefix("data: ").unwrap().trim_end()).unwrap();
    assert_eq!(error["id"], 7);
    assert_eq!(error["error"]["code"], -32001);
    assert_eq!(r.take_settled(), vec![TaskSettled::Failed]);
    assert_eq!(
        r.on_piece(far(None, &[], true)),
        PieceAnswer::Nothing,
        "it ends once"
    );

    let mut ok = streaming();
    let _ = ok.on_piece(far(None, &stream_event(pb::TaskState::Working), false));
    let _ = ok.take_settled();
    let _ = ok.on_far_fields(&[], Some(0), false);
    let end = part(ok.on_piece(far(None, &[], true)));
    assert!(end.last && end.body.is_empty());
    assert_eq!(ok.take_settled(), Vec::new());
}

/// A STREAM MESSAGE THE PLANE CANNOT READ REFUSES THE HOP, never stepped over or waited on: a
/// compressed message before any event refuses it outright, its task failed; an undecodable one
/// after the events began ends the answer there, its task failed.
#[test]
fn an_unreadable_grpc_stream_message_refuses_the_hop() {
    let mut compressed = stream_event(pb::TaskState::Working);
    compressed[0] = 1;
    let mut before = streaming();
    let PieceAnswer::ToCaller(reply) = before.on_piece(far(None, &compressed, false)) else {
        panic!("refused before the answer started");
    };
    assert_eq!(reply.status, 502);
    assert_eq!(before.take_settled(), vec![TaskSettled::Failed]);

    let mut after = streaming();
    let mut pieces = stream_event(pb::TaskState::Working);
    pieces.extend_from_slice(&[0, 0, 0, 0, 2, 0xff, 0xff]);
    pieces.extend_from_slice(&stream_event(pb::TaskState::Completed));
    let end = part(after.on_piece(far(None, &pieces, false)));
    assert!(
        end.head && end.last,
        "the event read goes out and the answer ends"
    );
    assert_eq!(
        String::from_utf8_lossy(&end.body).matches("data: ").count(),
        1,
        "nothing after the unreadable message is relayed"
    );
    assert_eq!(
        after.take_settled().last(),
        Some(&TaskSettled::Failed),
        "the task fails"
    );
}

#[test]
fn unary_grpc_refuses_missing_status_extra_messages_and_trailing_bytes() {
    for messages in [
        vec![
            send_answer(pb::TaskState::Completed),
            send_answer(pb::TaskState::Completed),
        ],
        vec![{
            let mut bytes = send_answer(pb::TaskState::Completed);
            bytes.push(0);
            bytes
        }],
    ] {
        let (mut hop, _, _) = dialled(&submission("SendMessage"), None, false);
        let reply = whole(answer(&mut hop, &messages, Some(0)));
        assert!(body(&reply).get("error").is_some());
        assert!(body(&reply).get("result").is_none());
    }
    let (mut hop, _, _) = dialled(&submission("SendMessage"), None, false);
    let reply = whole(answer(
        &mut hop,
        &[send_answer(pb::TaskState::Completed)],
        None,
    ));
    assert_eq!(reply.status, 502);
    assert!(body(&reply).get("error").is_some());
    assert!(body(&reply).get("result").is_none());
    assert_eq!(hop.take_reading(), Some(Reading::Transient));
}

#[test]
fn grpc_stream_http_refusal_records_the_http_health_signal() {
    let (mut relay, _, _) = dialled(&submission("SendStreamingMessage"), None, true);
    let reply = whole(vec![relay.on_piece(far(
        Some(401),
        b"not a protobuf message",
        true,
    ))]);
    assert_eq!(reply.status, 502);
    assert_eq!(relay.take_reading(), Some(Reading::Hard));
}

#[test]
fn grpc_trailer_error_info_cannot_borrow_an_a2a_reason_from_another_domain() {
    use crate::framed::{CallStatus, Code, ErrorInfo, DETAILS_FIELD};
    use base64::Engine as _;
    for (domain, status, reason, expected_http, expected_code, reading) in [
        (
            crate::ERROR_INFO_DOMAIN,
            Code::Internal,
            "TASK_NOT_FOUND",
            404,
            -32001,
            Reading::Transient,
        ),
        (
            "other.example",
            Code::Internal,
            "TASK_NOT_FOUND",
            500,
            -32603,
            Reading::Transient,
        ),
        (
            "other.example",
            Code::NotFound,
            "TASK_NOT_CANCELABLE",
            404,
            -32001,
            Reading::Healthy,
        ),
    ] {
        let asked = json!({"jsonrpc":"2.0","id":7,"method":"GetTask","params":{"id":BACKEND}});
        let (mut relay, _, _) = dialled(&asked, None, false);
        relay.for_task(TaskHop {
            task_id: "busbar-t".into(),
            context_id: "busbar-c".into(),
            addressed: true,
            skill: None,
            references: Vec::new(),
        });
        let details = CallStatus::with_error_info(
            status,
            "private backend words",
            ErrorInfo {
                domain: domain.into(),
                reason: reason.into(),
                metadata: std::collections::BTreeMap::new(),
            },
        );
        let block = format!(
            "{DETAILS_FIELD}: {}\r\n",
            base64::engine::general_purpose::STANDARD_NO_PAD.encode(details.details())
        );
        assert_eq!(
            relay.on_piece(far(Some(0), &[], false)),
            PieceAnswer::Nothing
        );
        let reply = whole(vec![relay.on_far_fields(
            block.as_bytes(),
            Some(status as u32),
            true,
        )]);
        assert_eq!(
            (reply.status, body(&reply)["error"]["code"].as_i64()),
            (expected_http, Some(expected_code))
        );
        assert_eq!(relay.take_reading(), Some(reading));
        assert!(
            relay.take_settled().is_empty(),
            "an addressed task remains held"
        );
        let text = std::str::from_utf8(&reply.body).unwrap();
        assert!(!text.contains("other.example") && !text.contains("private backend words"));
    }
}
