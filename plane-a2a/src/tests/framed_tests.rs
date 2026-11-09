// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The gRPC line's codec: the service path, the transcoding both ways, and the status table it
//! answers with (the engine's `grpc_tests.rs`, ported).

use super::*;
use crate::proto::pb;

/// What a test reads back off a status.
impl CallStatus {
    /// The encoded `google.rpc.Status` details; empty when there are none.
    #[must_use]
    pub(crate) fn details(&self) -> &[u8] {
        &self.details
    }

    /// The `ErrorInfo` the details carry, read back.
    #[must_use]
    pub(crate) fn error_info(&self) -> Option<ErrorInfo> {
        let status = rpc::Status::decode(self.details.as_slice()).ok()?;
        status
            .details
            .iter()
            .find(|any| any.type_url == crate::ERROR_INFO_TYPE)
            .and_then(|any| ErrorInfo::decode(any.value.as_slice()).ok())
    }
}

/// THE PATH IS THE `.proto`'S: the generated service's own constant, never a literal typed twice.
#[test]
fn the_service_path_is_the_generated_services() {
    assert_eq!(
        SERVICE_PATH.strip_prefix('/'),
        Some(crate::proto::SERVICE_NAME)
    );
    assert_eq!(
        crate::statement::ROUTES
            .iter()
            .filter(|r| r.carrier == crate::claims::FRAMED_TRANSPORT)
            .map(|r| r.target)
            .collect::<Vec<_>>(),
        [format!("{SERVICE_PATH}/{{method}}").as_str()]
    );
}

/// Every rpc is found by its target, and nothing else is.
#[test]
fn an_rpc_is_named_by_its_target_alone() {
    for rpc in RPCS {
        assert_eq!(
            Rpc::of_target(&format!("{SERVICE_PATH}/{}", rpc.name())),
            Some(rpc)
        );
    }
    assert_eq!(Rpc::of_target(&format!("{SERVICE_PATH}/Nope")), None);
    assert_eq!(Rpc::of_target("/other.Service/SendMessage"), None);
    assert_eq!(Rpc::of_target(SERVICE_PATH), None);
    assert!(Rpc::SendStreamingMessage.streams() && Rpc::SubscribeToTask.streams());
    assert!(!Rpc::SendMessage.streams());
    assert_eq!(unimplemented().code(), Code::Unimplemented);
}

/// A REQUEST MESSAGE IS THE v1.0 JSON-RPC REQUEST IT IS: the rpc's name as the method, its
/// ProtoJSON as the params.
#[test]
fn a_request_message_composes_the_json_rpc_request_it_is() {
    let message = crate::proto::custody::initialized::<pb::GetTaskRequest>(|__custody_message| {
        __custody_message.id = "t-1".into();
        __custody_message.history_length = Some(2);
    })
    .encode_to_vec();
    let composed: Value =
        serde_json::from_slice(&compose(Rpc::GetTask, &message).expect("composes")).unwrap();
    assert_eq!(composed["jsonrpc"], "2.0");
    assert_eq!(composed["id"], COMPOSED_ID);
    assert_eq!(composed["method"], "GetTask");
    assert_eq!(composed["params"]["id"], "t-1");
    assert_eq!(composed["params"]["historyLength"], 2);
}

/// Bytes that are not the rpc's message are `INTERNAL`, as the engine mapped a protobuf parse error.
#[test]
fn a_message_that_does_not_decode_is_internal() {
    let status = compose(Rpc::GetTask, &[0xff, 0xff, 0xff]).expect_err("refused");
    assert_eq!(status.code(), Code::Internal);
}

/// THE ANSWER'S RESULT IS THE RPC'S RESPONSE MESSAGE, in its protobuf bytes.
#[test]
fn a_result_answers_the_rpcs_response_message() {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": COMPOSED_ID,
        "result": { "id": "t-1", "contextId": "c-1", "status": { "state": "TASK_STATE_COMPLETED" } },
    });
    let bytes = answer_message(Rpc::GetTask, 200, body.to_string().as_bytes()).expect("answers");
    let task = pb::Task::decode(bytes.as_slice()).expect("a Task");
    assert_eq!(task.id, "t-1");
    assert_eq!(task.context_id, "c-1");

    let deleted = serde_json::json!({ "jsonrpc": "2.0", "id": 1, "result": null });
    assert_eq!(
        answer_message(
            Rpc::DeleteTaskPushNotificationConfig,
            200,
            deleted.to_string().as_bytes()
        )
        .expect("answers"),
        Vec::<u8>::new()
    );
}

/// THE JSON-RPC CODE DECIDES, not the HTTP status.
#[test]
fn a_json_rpc_error_takes_its_status_from_its_code() {
    let err = serde_json::json!({ "code": -32002, "message": "the task is terminal" });
    let status = status_for_error(&err, 409);
    assert_eq!(status.code(), Code::FailedPrecondition);
    assert_eq!(status.message(), "the task is terminal");
    let body = serde_json::json!({ "jsonrpc": "2.0", "id": 1, "error": err });
    let refused =
        answer_message(Rpc::CancelTask, 409, body.to_string().as_bytes()).expect_err("an error");
    assert_eq!(refused.code(), Code::FailedPrecondition);
}

/// EVERY A2A ERROR HAS section 5.4's gRPC STATUS.
#[test]
fn the_error_table_carries_the_specifications_grpc_column() {
    let rows = [
        (-32001, Code::NotFound),
        (-32002, Code::FailedPrecondition),
        (-32003, Code::FailedPrecondition),
        (-32004, Code::FailedPrecondition),
        (-32005, Code::InvalidArgument),
        (-32006, Code::Internal),
        (-32007, Code::FailedPrecondition),
        (-32008, Code::FailedPrecondition),
        (-32009, Code::Unimplemented),
        (-32600, Code::InvalidArgument),
        (-32601, Code::Unimplemented),
        (-32602, Code::InvalidArgument),
        (-32603, Code::Internal),
        (-32700, Code::InvalidArgument),
    ];
    for (code, want) in rows {
        assert_eq!(grpc_code(code), Some(want), "code {code}");
    }
    assert_eq!(grpc_code(-31000), None);
}

/// A CODE A2A DOES NOT DEFINE falls back to the HTTP status.
#[test]
fn an_unknown_json_rpc_code_falls_back_to_the_http_status() {
    let err = serde_json::json!({ "code": -31000, "message": "vendor error" });
    assert_eq!(status_for_error(&err, 503).code(), Code::Unavailable);
}

#[test]
fn a_kernel_limit_or_open_breaker_is_retryable_not_an_unimplemented_method() {
    use base64::Engine as _;
    for (http, message) in [(429, "this key is over its budget"), (503, "breaker_open")] {
        let mut envelope = crate::agent_arrival::kernel_refusal(http, message).envelope();
        envelope["error"]["data"][0]["metadata"] = serde_json::json!({"cause": "local refusal"});
        let reply = refusal(envelope.to_string().as_bytes(), http);
        assert_eq!(reply.code, Code::Unavailable as u32);
        assert_eq!(reply.body.as_slice(), message.as_bytes());
        assert!(String::from_utf8_lossy(&status_block(&reply)).contains("grpc-status: 14\r\n"));
        let details = base64::engine::general_purpose::STANDARD_NO_PAD
            .decode(
                reply
                    .details
                    .as_ref()
                    .expect("the real refusal carries ErrorInfo"),
            )
            .expect("base64 status details");
        let status = rpc::Status::decode(details.as_slice()).expect("a google.rpc.Status");
        assert_eq!(status.code, Code::Unavailable as i32);
        assert_eq!(status.message, message);
        let detail = status
            .details
            .first()
            .expect("the original ErrorInfo is retained");
        assert_eq!(detail.type_url, crate::ERROR_INFO_TYPE);
        let info = ErrorInfo::decode(detail.value.as_slice()).expect("the original ErrorInfo");
        assert_eq!(info.reason, "UNSUPPORTED_OPERATION");
        assert_eq!(info.domain, crate::ERROR_INFO_DOMAIN);
        assert_eq!(
            info.metadata.get("cause").map(String::as_str),
            Some("local refusal")
        );
    }
    let unsupported = serde_json::json!({"code": -32004, "message": "streaming is not supported"});
    for http in [400, 501] {
        assert_eq!(
            status_for_error(&unsupported, http).code(),
            Code::FailedPrecondition
        );
    }
    let unknown_method = serde_json::json!({"code": -32601, "message": "no such method"});
    assert_eq!(
        status_for_error(&unknown_method, 404).code(),
        Code::Unimplemented
    );
    let envelope = serde_json::json!({"jsonrpc": "2.0", "id": 1, "error": unsupported});
    let frame = format!("data: {envelope}\n\n");
    let error = event(&frame)
        .expect("an error event")
        .expect_err("unsupported operation");
    assert_eq!(
        error.code(),
        Code::FailedPrecondition,
        "the upstream stream's real protocol error"
    );
    let error = answer_message(Rpc::SendMessage, 500, envelope.to_string().as_bytes())
        .expect_err("an upstream unsupported-operation answer");
    assert_eq!(
        error.code(),
        Code::FailedPrecondition,
        "the upstream answer's real protocol error"
    );
}

/// An answer that is not a JSON-RPC answer takes the gRPC specification's own HTTP mapping.
#[test]
fn an_http_refusal_takes_the_grpc_specifications_own_mapping() {
    for (http, want) in [
        (401, Code::Unauthenticated),
        (403, Code::PermissionDenied),
        (404, Code::Unimplemented),
        (413, Code::ResourceExhausted),
        (503, Code::Unavailable),
        (400, Code::Internal),
        (418, Code::Unknown),
    ] {
        assert_eq!(status_for_http(http).code(), want, "HTTP {http}");
    }
    assert_eq!(
        answer_message(Rpc::GetTask, 502, b"not json")
            .expect_err("refused")
            .code(),
        Code::Unavailable
    );
}

/// AN A2A REFUSAL CARRIES ITS `google.rpc.ErrorInfo` IN THE STATUS DETAILS (A2A 10.6, TCK
/// `GRPC-ERR-001`), transcribed from the envelope with its metadata.
#[test]
fn an_a2a_refusal_carries_error_info_in_the_status_details() {
    let err = serde_json::json!({
        "code": -32001,
        "message": "no task with id t-404",
        "data": [{
            "@type": crate::ERROR_INFO_TYPE,
            "domain": crate::ERROR_INFO_DOMAIN,
            "reason": "TASK_NOT_FOUND",
            "metadata": { "taskId": "t-404" },
        }],
    });
    let status = status_for_error(&err, 404);
    assert_eq!(status.code(), Code::NotFound);
    let info = status.error_info().expect("ErrorInfo in the details");
    assert_eq!(info.reason, "TASK_NOT_FOUND");
    assert_eq!(info.domain, crate::ERROR_INFO_DOMAIN);
    assert_eq!(
        info.metadata.get("taskId").map(String::as_str),
        Some("t-404")
    );
}

/// AND A STANDARD JSON-RPC ERROR CARRIES NONE.
#[test]
fn a_standard_json_rpc_error_carries_no_error_info() {
    let err = serde_json::json!({ "code": -32602, "message": "params are malformed" });
    let status = status_for_error(&err, 400);
    assert!(status.error_info().is_none());
    assert!(status.details().is_empty());
}

/// ONE EVENT IS ONE `StreamResponse`; a frame with no result is skipped; an error ends the stream.
#[test]
fn an_event_is_one_stream_response() {
    let frame = format!(
        "data: {}",
        serde_json::json!({
            "jsonrpc": "2.0", "id": 1,
            "result": { "task": { "id": "t-1", "contextId": "c-1",
                                   "status": { "state": "TASK_STATE_WORKING" } } },
        })
    );
    let bytes = event(&frame).expect("an event").expect("a message");
    let response = pb::StreamResponse::decode(bytes.as_slice()).expect("a StreamResponse");
    assert!(response.payload.is_some());
    assert!(event(": keep-alive").is_none());
    let failed = format!(
        "data: {}",
        serde_json::json!({ "jsonrpc": "2.0", "id": 1,
                            "error": { "code": -32001, "message": "gone" } })
    );
    assert_eq!(
        event(&failed).expect("an event").expect_err("ends").code(),
        Code::NotFound
    );
}

/// THE CARD NARROWING removes only the member the proto has no field for.
#[test]
fn the_card_narrowing_removes_only_the_member_the_proto_has_no_field_for() {
    let card = serde_json::json!({
        "name": "busbar",
        "capabilities": {
            "streaming": true,
            "pushNotifications": true,
            "stateTransitionHistory": true,
            "extendedAgentCard": true,
        },
        "skills": [{ "id": "planner" }],
    });
    let narrowed = narrowed_to_the_proto(card);
    assert!(narrowed["capabilities"]
        .get("stateTransitionHistory")
        .is_none());
    for kept in ["streaming", "pushNotifications", "extendedAgentCard"] {
        assert_eq!(narrowed["capabilities"][kept], Value::Bool(true), "{kept}");
    }
    assert_eq!(narrowed["skills"][0]["id"], "planner");
}

/// Neither send RPC can turn an absent required message into a new user request.
#[test]
fn a_send_with_no_message_is_invalid_argument() {
    let none = pb::SendMessageRequest::default().encode_to_vec();
    for rpc in [Rpc::SendMessage, Rpc::SendStreamingMessage] {
        let refusal = compose(rpc, &none).expect_err("message is required");
        assert_eq!(refusal.code(), Code::InvalidArgument);
        assert!(refusal.message().contains("SendMessageRequest.message"));
    }
}

/// A supplied message keeps its identity; the legacy mint helper is not selected for it.
#[test]
fn a_supplied_send_message_keeps_the_callers_identity() {
    let some = crate::proto::custody::initialized::<pb::SendMessageRequest>(|__custody_message| {
        __custody_message.message = Some(crate::proto::custody::initialized::<pb::Message>(
            |__custody_message| {
                __custody_message.message_id = "caller-message".into();
                __custody_message.role = pb::Role::User as i32;
            },
        ));
    })
    .encode_to_vec();
    assert!(!mints_message_id(Rpc::SendMessage, &some));
    for rpc in [Rpc::SendMessage, Rpc::SendStreamingMessage] {
        let composed: Value =
            serde_json::from_slice(&compose(rpc, &some).expect("composes")).unwrap();
        assert_eq!(composed["params"]["message"]["messageId"], "caller-message");
        assert_eq!(composed["params"]["message"]["role"], "ROLE_USER");
    }
}

#[test]
fn the_legacy_message_id_helper_uses_a_v7_uuid() {
    let id = message_id_v7(0x0190_1234_5678, &[0xff; 10]);
    assert_eq!(id, "01901234-5678-7fff-bfff-ffffffffffff");
    let composed = serde_json::json!({"params":{"message":{"role":"ROLE_USER"}}});
    let minted = with_message_id(&composed, &id);
    assert_eq!(minted["params"]["message"]["messageId"], id);
    assert_eq!(minted["params"]["message"]["role"], "ROLE_USER");
    assert!(minted["params"]["message"].get("parts").is_none());
}

/// The next complete frame of `buf`, consumed from it using the shared SSE parser.
fn take_frame(buf: &mut Vec<u8>) -> Option<String> {
    let mut frames = busbar_contract::protocol::SseFrames::new();
    frames.push(buf);
    let span = frames.next_span()?;
    let frame = String::from_utf8_lossy(&frames.buffer()[span]).into_owned();
    let consumed = buf.len() - frames.pending();
    buf.drain(..consumed);
    Some(frame)
}

/// SSE FRAMES ARE TAKEN WHOLE OR NOT AT ALL (the engine's `grpc_tests.rs`, ported): a frame split
/// across two chunks is not delivered as two, and a buffer holding half a frame yields nothing
/// rather than a truncated one.
#[test]
fn a_frame_is_taken_only_once_it_is_complete() {
    let mut buf = b"data: {\"a\":1}\n\ndata: {\"b\"".to_vec();
    assert_eq!(take_frame(&mut buf).as_deref(), Some("data: {\"a\":1}\n\n"));
    assert_eq!(take_frame(&mut buf), None);
    buf.extend_from_slice(b":2}\n\n");
    assert_eq!(take_frame(&mut buf).as_deref(), Some("data: {\"b\":2}\n\n"));
    assert_eq!(take_frame(&mut buf), None);
}

/// AND IN EVERY LINE ENDING THE SSE GRAMMAR ALLOWS (the engine's `grpc_tests.rs`, ported): a
/// backend that frames with CRLF or CR is not a broken backend.
#[test]
fn every_sse_frame_terminator_is_recognised() {
    for terminator in ["\r\n\r\n", "\n\n", "\r\r"] {
        let expected = format!("data: {{\"x\":1}}{terminator}");
        let mut buf = format!("{expected}:").into_bytes();
        assert_eq!(
            take_frame(&mut buf).as_deref(),
            Some(expected.as_str()),
            "terminator {terminator:?} was not recognised"
        );
        assert_eq!(buf, b":");
    }
}
/// Ported from busbar-a2a a2a/tests/served_methods_tests.rs::the_extended_card_is_served_over_grpc_at_the_path_the_proto_defines.
/// The door's half of the gRPC binding: the generated service's own path names the rpc, and busbar's
/// extended card (the document the JSON-RPC line answers) comes back as the proto's `AgentCard`
/// message, preserving the skills supplied in that document. Caller entitlement filtering is
/// outside this transcode test.
#[test]
fn the_extended_card_is_served_over_grpc_at_the_path_the_proto_defines() {
    let target = format!("{SERVICE_PATH}/GetExtendedAgentCard");
    assert_eq!(Rpc::of_target(&target), Some(Rpc::GetExtendedAgentCard));

    let skill = serde_json::json!({
        "id": "planner", "name": "planner", "description": "plans", "tags": ["agent"],
        "inputModes": ["text/plain"], "outputModes": ["text/plain"],
    });
    let card = crate::served_card::extended_card_document("https://gw.example", &[])
        .map(|mut c| {
            c["skills"] = serde_json::json!([skill]);
            c
        })
        .expect("busbar's extended card");
    let envelope = serde_json::json!({ "jsonrpc": "2.0", "id": 1, "result": card });
    let bytes = answer_message(
        Rpc::GetExtendedAgentCard,
        200,
        envelope.to_string().as_bytes(),
    )
    .expect("the card answers as a message");
    let message = pb::AgentCard::decode(bytes.as_slice()).expect("an AgentCard");
    assert_eq!(
        message.name, "busbar",
        "the answer is busbar's own agent card"
    );
    assert_eq!(
        message
            .skills
            .iter()
            .map(|s| s.id.as_str())
            .collect::<Vec<_>>(),
        ["planner"],
        "the transcode preserves the document's skill ids"
    );
}

#[test]
fn null_error_is_not_a_terminal_event_and_an_unfinished_frame_is_not_dispatched() {
    assert!(event(r#"data: {"error":null}"#).is_none());
    let tail = br#"data: {"error":{"code":-32603,"message":"failure"}}"#;
    assert_eq!(
        event_messages(Rpc::SendStreamingMessage, tail),
        (Vec::new(), None)
    );
    let mut complete = tail.to_vec();
    complete.extend_from_slice(b"\n\n");
    assert!(event_messages(Rpc::SendStreamingMessage, &complete)
        .1
        .is_some());
}

#[test]
fn protojson_backend_errors_do_not_echo_backend_bytes() {
    let bytes = br#"{"jsonrpc":"2.0","id":1,"result":{"secret-backend-member":true}}"#;
    let error = answer_message(Rpc::GetTask, 200, bytes).unwrap_err();
    assert!(!format!("{error:?}").contains("secret-backend-member"));
}

#[test]
fn null_error_does_not_override_unary_result() {
    assert!(answer_message(
        Rpc::DeleteTaskPushNotificationConfig,
        200,
        br#"{"result":{},"error":null}"#
    )
    .is_ok());
}

#[test]
fn invalid_json_event_is_an_explicit_stream_failure() {
    assert!(matches!(event("data: not-json"), Some(Err(_))));
    assert!(event(": heartbeat").is_none());
}
