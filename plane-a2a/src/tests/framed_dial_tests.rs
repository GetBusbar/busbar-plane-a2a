// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The gRPC line's codec in the direction that DIALS: the hop's params as the rpc's request
//! message, each answered message as its ProtoJSON result, the length prefix, and the status the
//! trailers state (the engine's `relay::GrpcFraming`). The oracle is the generated `pb` messages,
//! decoded and encoded with `prost` directly, never this module's own reader.

use super::*;
use crate::proto::pb;
use serde_json::json;

#[test]
fn outbound_sends_refuse_an_absent_or_null_message() {
    for rpc in [Rpc::SendMessage, Rpc::SendStreamingMessage] {
        for params in [json!({}), json!({"message": null})] {
            assert!(request_message(rpc, &params).is_err());
        }
        let params = json!({"message": {
            "messageId": "caller-message",
            "role": "ROLE_USER",
            "parts": [{"text": "the supplied message"}]
        }});
        let bytes = request_message(rpc, &params).expect("a supplied message is carried");
        let request = pb::SendMessageRequest::decode(bytes.as_slice()).unwrap();
        assert_eq!(
            request.message.as_ref().unwrap().message_id,
            "caller-message"
        );
    }
}

/// Both A2A dialects name the same rpc; a method the service does not have names none.
#[test]
fn a_method_in_either_dialect_names_its_rpc() {
    for rpc in RPCS {
        assert_eq!(Rpc::of_method(rpc.name()), Some(rpc));
    }
    assert_eq!(Rpc::of_method("message/send"), Some(Rpc::SendMessage));
    assert_eq!(
        Rpc::of_method("message/stream"),
        Some(Rpc::SendStreamingMessage)
    );
    assert_eq!(
        Rpc::of_method("tasks/resubscribe"),
        Some(Rpc::SubscribeToTask)
    );
    assert_eq!(
        Rpc::of_method("agent/getAuthenticatedExtendedCard"),
        Some(Rpc::GetExtendedAgentCard)
    );
    assert_eq!(Rpc::of_method("vendor/Thing"), None);
    assert_eq!(
        Rpc::of_target("/lf.a2a.v1.A2AService/GetTask"),
        Some(Rpc::GetTask),
    );
    assert_eq!(Rpc::of_target("/a2a.v1.A2AService/GetTask"), None);
    assert_eq!(
        Rpc::GetTask.target(),
        "/lf.a2a.v1.A2AService/GetTask",
        "the service's own path, absolute"
    );
}

/// THE HOP'S PARAMS ARE THE REQUEST MESSAGE: a v1.0 send's content survives the transcode, and a
/// task read names exactly the id the params name.
#[test]
fn the_params_are_written_as_the_rpcs_request_message() {
    let params = json!({
        "message": {
            "messageId": "m-1",
            "role": "ROLE_USER",
            "parts": [{ "text": "PLAN THE MIGRATION" }]
        }
    });
    let bytes = request_message(Rpc::SendMessage, &params).expect("a send is written");
    let sent = pb::SendMessageRequest::decode(bytes.as_slice()).expect("it decodes");
    let message = sent.message.as_ref().expect("the message");
    assert_eq!(message.message_id, "m-1");
    assert_eq!(message.role, pb::Role::User as i32);
    assert_eq!(
        message.parts[0].content,
        Some(pb::part::Content::Text("PLAN THE MIGRATION".into()))
    );
    let bytes = request_message(Rpc::GetTask, &json!({ "id": "BACKEND-OWN-TASK-ID" }))
        .expect("a read is written");
    assert_eq!(
        pb::GetTaskRequest::decode(bytes.as_slice())
            .expect("it decodes")
            .id,
        "BACKEND-OWN-TASK-ID"
    );
    let config = json!({
        "taskId": "b-1", "id": "busbar-b-1", "url": "https://busbar.example/a2a/push",
        "authentication": { "scheme": "Bearer", "credentials": "t-1.sig" },
    });
    let bytes = request_message(Rpc::CreateTaskPushNotificationConfig, &config)
        .expect("a config is written");
    let sent = pb::TaskPushNotificationConfig::decode(bytes.as_slice()).expect("it decodes");
    assert_eq!(
        (sent.task_id.as_str(), sent.id.as_str(), sent.url.as_str()),
        ("b-1", "busbar-b-1", "https://busbar.example/a2a/push")
    );
    assert_eq!(
        sent.authentication.as_ref().map(|a| a.credentials.as_str()),
        Some("t-1.sig")
    );

    let v03 = json!({ "message": { "kind": "message", "role": "user", "parts": [] } });
    assert!(request_message(Rpc::SendMessage, &v03).is_err());
}

/// EACH ANSWERED MESSAGE IS ITS RESULT: the rpc's response message read back as ProtoJSON; a
/// delete's `Empty` is `null`; a message that is not the rpc's response is refused.
#[test]
fn an_answered_message_is_read_as_the_rpcs_result() {
    let task = crate::proto::custody::initialized::<pb::Task>(|__custody_message| {
        __custody_message.id = "BACKEND-OWN-TASK-ID".into();
        __custody_message.context_id = "BACKEND-OWN-CONTEXT".into();
        __custody_message.status = Some(crate::proto::custody::initialized::<pb::TaskStatus>(
            |__custody_message| {
                __custody_message.state = pb::TaskState::Completed as i32;
            },
        ));
    });
    let answer = pb::SendMessageResponse {
        payload: Some(pb::send_message_response::Payload::Task(task.clone())),
    }
    .encode_to_vec();
    let result = response_result(Rpc::SendMessage, &answer).expect("it reads");
    assert_eq!(result["task"]["id"], "BACKEND-OWN-TASK-ID");
    assert_eq!(result["task"]["status"]["state"], "TASK_STATE_COMPLETED");
    let read = response_result(Rpc::GetTask, &task.encode_to_vec()).expect("it reads");
    assert_eq!(read["contextId"], "BACKEND-OWN-CONTEXT");
    assert_eq!(
        response_result(Rpc::DeleteTaskPushNotificationConfig, &[]),
        Ok(Value::Null)
    );
    assert!(response_result(Rpc::GetTask, &[0xff, 0xff, 0xff]).is_err());

    assert!(response_result(Rpc::SendMessage, &[]).is_err());
}

/// THE LENGTH PREFIX: a message is taken only once it is whole; a compressed one is refused.
#[test]
fn a_message_is_taken_whole_off_its_length_prefix() {
    let mut buf = vec![0, 0, 0, 0, 3, b'a', b'b'];
    assert_eq!(take_message(&buf), Ok(None));
    buf.push(b'c');
    assert_eq!(take_message(&buf), Ok(Some((3, 8))));
    assert_eq!(take_message(&[0, 0, 0]), Ok(None));
    assert_eq!(take_message(&[0, 0, 0, 0, 0]), Ok(Some((0, 5))));
    assert!(take_message(&[1, 0, 0, 0, 0]).is_err());

    assert!(take_message(&[0, 0xff, 0xff, 0xff, 0xff]).is_err());
}

/// The trailers' field block, `name: value` per line, as the grpc transport renders it.
fn block(fields: &[(&str, &str)]) -> Vec<u8> {
    use busbar_contract::abi::transport::fields::{LINE_END, SEPARATOR};
    let mut out = Vec::new();
    for (name, value) in fields {
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(SEPARATOR);
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(LINE_END);
    }
    out
}

/// THE STATUS THE TRAILERS STATE: the code the host passes beside them (the kernel hands on the
/// status the transport read off them), with the `ErrorInfo` of the details' `google.rpc.Status`.
/// The details never state the code: trailers handed on with no status state nothing, whatever
/// their details say (RED: the details' own code was read as the call's status).
#[test]
fn the_trailers_state_the_calls_status_and_its_error_info() {
    use base64::Engine as _;
    assert_eq!(ended(&[], None), None);
    assert_eq!(
        ended(&[], Some(0)),
        Some(Ended {
            code: 0,
            info: None
        })
    );
    assert!(ended(&[], Some(0)).is_some_and(|e| e.ok()));
    let refused = CallStatus::with_error_info(
        Code::NotFound,
        "no such task",
        ErrorInfo {
            reason: "TASK_NOT_FOUND".into(),
            domain: crate::ERROR_INFO_DOMAIN.into(),
            metadata: std::collections::BTreeMap::new(),
        },
    );
    let details = base64::engine::general_purpose::STANDARD_NO_PAD.encode(refused.details());
    let trailers = block(&[("x-other", "1"), (DETAILS_FIELD, &details)]);
    assert_eq!(
        ended(&trailers, None),
        None,
        "the details are no status of their own"
    );
    let got = ended(&trailers, Some(Code::NotFound as u32)).expect("the stated status");
    assert_eq!(got.code, Code::NotFound as u32);
    assert_eq!(
        got.info.as_ref().map(|i| i.reason.as_str()),
        Some("TASK_NOT_FOUND")
    );
    assert_eq!(got.a2a_code(), Some(-32001));

    let padded = base64::engine::general_purpose::STANDARD.encode(refused.details());
    let stated = ended(&block(&[(DETAILS_FIELD, &padded)]), Some(14)).expect("stated");
    assert_eq!(stated.code, 14);
    assert_eq!(
        stated.info.as_ref().map(|i| i.reason.as_str()),
        Some("TASK_NOT_FOUND")
    );
    assert_eq!(ended(&block(&[("x-other", "1")]), None), None);
}

/// THE A2A CODE A STATUS CARRIES: the reason's, else the one section 5.4 binds to the status
/// alone; a status several A2A codes share, with no reason, names none.
#[test]
fn a_status_names_the_a2a_code_its_reason_or_its_row_binds() {
    let bare = |code: Code| Ended {
        code: code as u32,
        info: None,
    };
    assert_eq!(bare(Code::NotFound).a2a_code(), Some(-32001));
    assert_eq!(bare(Code::FailedPrecondition).a2a_code(), None);
    assert_eq!(bare(Code::Unimplemented).a2a_code(), Some(-32601));
    assert_eq!(bare(Code::Unavailable).a2a_code(), None);
    let reasoned = Ended {
        code: Code::FailedPrecondition as u32,
        info: Some(ErrorInfo {
            reason: "TASK_NOT_CANCELABLE".into(),
            domain: crate::ERROR_INFO_DOMAIN.into(),
            metadata: std::collections::BTreeMap::new(),
        }),
    };
    assert_eq!(reasoned.a2a_code(), Some(-32002));
}

#[test]
fn grpc_error_reasons_are_scoped_to_the_a2a_domain_and_other_domains_keep_status_fallback() {
    for (domain, code, reason, expected) in [
        (
            crate::ERROR_INFO_DOMAIN,
            Code::Internal,
            "TASK_NOT_FOUND",
            Some(-32001),
        ),
        ("other.example", Code::Internal, "TASK_NOT_FOUND", None),
        ("", Code::FailedPrecondition, "TASK_NOT_CANCELABLE", None),
        (
            "other.example",
            Code::NotFound,
            "TASK_NOT_CANCELABLE",
            Some(-32001),
        ),
        (
            crate::ERROR_INFO_DOMAIN,
            Code::NotFound,
            "UNKNOWN_REASON",
            Some(-32001),
        ),
    ] {
        let ended = Ended {
            code: code as u32,
            info: Some(ErrorInfo {
                domain: domain.into(),
                reason: reason.into(),
                metadata: std::collections::BTreeMap::new(),
            }),
        };
        assert_eq!(ended.a2a_code(), expected, "{domain:?} {code:?} {reason}");
    }
}

#[test]
fn grpc_message_length_ceiling_is_inclusive_and_enforced_before_waiting() {
    let length = crate::relay::MAX_REPLY_BYTES;
    let mut bytes = vec![0];
    bytes.extend_from_slice(&u32::try_from(length).unwrap().to_be_bytes());
    assert_eq!(take_message(&bytes), Ok(None));
    bytes.resize(MESSAGE_PREFIX + length, 0);
    assert_eq!(
        take_message(&bytes),
        Ok(Some((length, MESSAGE_PREFIX + length)))
    );
    let mut oversized = vec![0];
    oversized.extend_from_slice(&u32::try_from(length + 1).unwrap().to_be_bytes());
    assert!(take_message(&oversized).is_err());
}

#[test]
fn v101_precondition_errors_keep_their_identity_across_both_bindings() {
    use base64::Engine as _;
    for (code, reason) in [
        (-32003, "PUSH_NOTIFICATION_NOT_SUPPORTED"),
        (-32004, "UNSUPPORTED_OPERATION"),
        (-32009, "VERSION_NOT_SUPPORTED"),
    ] {
        let refusal = crate::agent_arrival::AgentRefusal::new(400, Some(json!(7)), code, "refused");
        assert_eq!(refusal.aip193()["error"]["status"], "FAILED_PRECONDITION");
        let error = refusal.envelope()["error"].clone();
        let status = status_for_error(&error, 400);
        assert_eq!(status.code(), Code::FailedPrecondition);
        let details = base64::engine::general_purpose::STANDARD_NO_PAD.encode(status.details());
        let received = ended(&block(&[(DETAILS_FIELD, &details)]), Some(9)).unwrap();
        assert_eq!(received.info.as_ref().unwrap().reason, reason);
        assert_eq!(received.a2a_code(), Some(code));
    }
    assert_eq!(grpc_code(-32601), Some(Code::Unimplemented));
}
