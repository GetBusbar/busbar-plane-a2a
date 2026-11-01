// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[test]
fn taskless_stream_refusals_use_the_stream_diagnostic_before_any_task_context() {
    for cause in ["transport", "binding", "status"] {
        let mut relay = HopRelay::new(json!(7), "1.0");
        relay.name_backend("taskless-stream-agent", URL);
        relay.expect_events();
        assert!(matches!(
            relay.on_piece(kernel(Some(URL))),
            PieceAnswer::Attempt(_)
        ));
        assert_eq!(relay.on_piece(caller(STREAM)), PieceAnswer::ToFarEndLent);
        assert!(relay.task().is_none());
        let (_, lines) = journaled(|| match cause {
            "transport" => relay.refuse_transport().0,
            "binding" => match relay.refuse_unspeakable("unsupported") {
                PieceAnswer::ToCaller(reply) => reply,
                other => panic!("{other:?}"),
            },
            _ => answered(&mut relay, 503, b"{}"),
        });
        let stream = crate::diagnostics::A2A_RELAYED_STREAM_REFUSED
            .banner()
            .to_string();
        let unary = crate::diagnostics::A2A_RELAYED_SUBMISSION_FAILED
            .banner()
            .to_string();
        assert!(
            lines
                .iter()
                .any(|(_, line)| line.contains(&stream) && line.contains("taskless-stream-agent")),
            "the refused stream has its own diagnostic without a task: {lines:?}"
        );
        assert!(
            lines.iter().all(|(_, line)| !line.contains(&unary)),
            "a streaming failure is never classified as a unary failure: {lines:?}"
        );
    }
}

#[test]
fn unary_taskless_reads_and_listings_keep_their_agent_and_refusal_context() {
    for method in [
        "GetTask",
        "ListTasks",
        "CancelTask",
        "tasks/get",
        "tasks/list",
    ] {
        let mut relay = sent();
        relay.name_backend("unary-operation-agent", URL);
        relay.bind(
            Binding::JsonRpc,
            &json!({"method":method, "params":{"id":"request-secret"}}),
        );
        assert!(relay.task().is_none());
        let (reply, lines) = journaled(|| relay.refuse_transport().0);
        assert!(reply.status >= 400);
        let banner = crate::diagnostics::A2A_RELAYED_SUBMISSION_FAILED
            .banner()
            .to_string();
        assert!(
            lines.iter().any(|(_, line)| line.contains(&banner)
                && line.contains("unary-operation-agent")
                && line.contains("error=")),
            "the generic request refusal remains observable: {lines:?}"
        );
        assert!(lines
            .iter()
            .all(|(_, line)| !line.contains("request-secret")));
    }
}

#[test]
fn a_dropped_sse_frame_identifies_the_actual_backend_without_logging_payload_bytes() {
    let (mut relay, _) = events_sent();
    relay.name_backend("malformed-sse-agent", URL);
    let mut bytes = b"data: payload-secret-must-not-be-logged\xff\n\n".to_vec();
    bytes.extend_from_slice(b"data: payload-secret-must-not-be-logged\xff\n\n");
    bytes.extend(event(
        json!({"kind":"status-update", "status":{"state":"working"}}),
    ));
    let (sent, heard) = std::sync::mpsc::channel();
    let output = tracing::subscriber::with_default(Capture(sent), || {
        part(relay.on_piece(far(Some(200), &bytes, false)))
    });
    let lines: Vec<_> = heard.try_iter().collect();
    let banner = crate::diagnostics::PLANE_SSE_FRAME_NOT_UTF8
        .banner()
        .to_string();
    assert!(
        lines
            .iter()
            .any(|(level, line)| *level == tracing::Level::WARN
                && line.contains(&banner)
                && line.contains("malformed-sse-agent")
                && line.contains("bytes=")),
        "the warning identifies the backend and dropped frame size: {lines:?}"
    );
    assert!(
        lines
            .iter()
            .all(|(_, line)| !line.contains("payload-secret")),
        "the malformed payload is never logged: {lines:?}"
    );
    assert!(
        String::from_utf8_lossy(&output.body).contains("working"),
        "a good event after the malformed one is still relayed"
    );
    assert!(!String::from_utf8_lossy(&output.body).contains("payload-secret"));
}
