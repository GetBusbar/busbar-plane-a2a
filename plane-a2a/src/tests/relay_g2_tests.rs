// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[test]
fn http_json_error_info_keeps_the_a2a_identity_and_the_carrier_breaker_reading() {
    for (code, status, reason, reading) in [
        (-32001, 404, "TASK_NOT_FOUND", Reading::Caller),
        (-32002, 400, "TASK_NOT_CANCELABLE", Reading::Caller),
        (
            -32003,
            400,
            "PUSH_NOTIFICATION_NOT_SUPPORTED",
            Reading::Caller,
        ),
        (-32004, 400, "UNSUPPORTED_OPERATION", Reading::Caller),
        (-32005, 400, "CONTENT_TYPE_NOT_SUPPORTED", Reading::Caller),
        (-32006, 500, "INVALID_AGENT_RESPONSE", Reading::Transient),
        (
            -32007,
            400,
            "EXTENDED_AGENT_CARD_NOT_CONFIGURED",
            Reading::Caller,
        ),
        (-32008, 400, "EXTENSION_SUPPORT_REQUIRED", Reading::Caller),
        (-32009, 400, "VERSION_NOT_SUPPORTED", Reading::Caller),
    ] {
        for addressed in [false, true] {
            let mut relay = rest_relay(Some(task(addressed)));
            assert!(matches!(
                relay.on_piece(kernel(Some(URL))),
                PieceAnswer::Attempt(_)
            ));
            assert_eq!(relay.on_piece(caller(GET)), PieceAnswer::Nothing);
            let wire = serde_json::to_vec(&json!({"error": {
                "code": status, "status": crate::agent_arrival::status_name_of(code).unwrap(), "message": "PRIVATE backend prose",
                "details": [{"@type": "type.googleapis.com/google.rpc.ErrorInfo",
                    "domain": "a2a-protocol.org", "reason": reason}]
            }})).unwrap();
            let reply = answered(&mut relay, status, &wire);
            let got = body(&reply);
            assert_eq!(
                (reply.status, got["error"]["code"].as_i64()),
                (status, Some(code))
            );
            assert_eq!(got["id"], 7);
            assert_eq!(got["error"]["data"][0]["reason"], reason);
            assert_eq!(relay.take_reading(), Some(reading));
            assert_eq!(relay.take_reading(), None);
            assert_eq!(relay.moved(), wire.len() as u64, "GET sent no payload");
            assert_eq!(
                relay.take_settled(),
                if addressed {
                    vec![]
                } else {
                    vec![TaskSettled::Failed]
                }
            );
            let text = String::from_utf8(reply.body.clone()).unwrap();
            assert!(!text.contains("PRIVATE") && !text.contains("vendor.example"));
            assert_eq!(
                relay.on_piece(far(None, b"late", true)),
                PieceAnswer::Nothing
            );
        }
    }
}

#[test]
fn http_json_does_not_guess_an_a2a_identity_from_http_status_or_foreign_details() {
    for details in [
        json!([]),
        json!([{"@type": "type.googleapis.com/google.rpc.ErrorInfo", "domain": "other.example", "reason": "TASK_NOT_FOUND"}]),
        json!([{"@type": "other.example/Info", "domain": "a2a-protocol.org", "reason": "TASK_NOT_FOUND"}]),
        json!([{"@type": "type.googleapis.com/google.rpc.ErrorInfo", "domain": "a2a-protocol.org", "reason": "UNKNOWN_REASON"}]),
    ] {
        let mut relay = rest_relay(Some(task(true)));
        let _ = relay.on_piece(kernel(Some(URL)));
        let wire = serde_json::to_vec(
            &json!({"error": {"code": 404, "status": "NOT_FOUND", "details": details}}),
        )
        .unwrap();
        let reply = answered(&mut relay, 404, &wire);
        assert_eq!(reply.status, 502);
        assert_eq!(body(&reply)["error"]["code"], -32006);
        assert_eq!(relay.take_reading(), Some(Reading::Caller));
        assert!(
            relay.take_settled().is_empty(),
            "an addressed task is unchanged"
        );
    }
}

#[test]
fn an_unreadable_http_json_reply_is_a_journaled_transient_backend_failure() {
    for task_hop in [None, Some(task(false)), Some(task(true))] {
        let mut relay = rest_relay(task_hop.clone());
        relay.name_backend("private-agent", URL);
        assert!(matches!(
            relay.on_piece(kernel(Some(URL))),
            PieceAnswer::Attempt(_)
        ));
        assert_eq!(relay.on_piece(caller(GET)), PieceAnswer::Nothing);
        let (reply, lines) = journaled(|| answered(&mut relay, 200, b"<html>PRIVATE</html>"));
        assert_eq!(reply.status, 502);
        assert_eq!(relay.take_reading(), Some(Reading::Transient));
        assert_eq!(relay.moved(), b"<html>PRIVATE</html>".len() as u64);
        assert_eq!(
            relay.take_settled(),
            if task_hop.as_ref().is_some_and(|t| !t.addressed) {
                vec![TaskSettled::Failed]
            } else {
                vec![]
            }
        );
        let text = String::from_utf8(reply.body.clone()).unwrap();
        assert!(
            !text.contains("unframable")
                && !text.contains("PRIVATE")
                && !text.contains("vendor.example")
        );
        if task_hop.is_none() {
            assert!(text.contains("a2a.hop.reply_not_json"), "{text}");
        }
        assert!(
            lines
                .iter()
                .any(|(level, line)| *level == tracing::Level::DEBUG
                    && line.contains(
                        &crate::diagnostics::A2A_RELAYED_SUBMISSION_FAILED
                            .banner()
                            .to_string()
                    )
                    && line.contains("private-agent")
                    && line.contains("[redacted]")),
            "the backend fault is journaled: {lines:?}"
        );
        assert!(lines
            .iter()
            .all(|(_, line)| !line.contains("vendor.example") && !line.contains("PRIVATE")));
    }
}

#[test]
fn valid_http_json_and_attempt_time_framing_keep_their_existing_outcomes() {
    let mut relay = rest_relay(None);
    let _ = relay.on_piece(kernel(Some(URL)));
    let reply = answered(
        &mut relay,
        200,
        br#"{"id":"t1","status":{"state":"working"}}"#,
    );
    assert_eq!(reply.status, 200);
    assert_eq!(body(&reply)["result"]["id"], "t1");
    assert_eq!(relay.take_reading(), Some(Reading::Healthy));

    let mut impossible = HopRelay::new(json!(7), "1.0");
    impossible.bind(Binding::HttpJson, &json!({"method":"vendor/Unknown"}));
    let PieceAnswer::ToCaller(reply) = impossible.on_piece(kernel(Some(URL))) else {
        panic!("the caller's unframable request is refused at the attempt");
    };
    assert!(body(&reply)["error"]["message"]
        .as_str()
        .unwrap()
        .contains("unframable"));
    assert_eq!(impossible.take_reading(), None);
    assert_eq!(impossible.moved(), 0);
}

#[test]
fn a_correlated_json_rpc_client_error_keeps_its_status_without_trusting_foreign_answers() {
    for (status, wire, expected, reading) in [
        (
            400,
            br#"{"jsonrpc":"2.0","id":7,"error":{"code":-32602,"message":"PRIVATE params"}}"#
                .as_slice(),
            400,
            Reading::Caller,
        ),
        (
            400,
            br#"{"jsonrpc":"2.0","id":8,"error":{"code":-32602,"message":"PRIVATE params"}}"#
                .as_slice(),
            502,
            Reading::Caller,
        ),
        (
            400,
            br#"{"jsonrpc":"1.0","id":7,"error":{"code":-32602,"message":"PRIVATE params"}}"#
                .as_slice(),
            502,
            Reading::Caller,
        ),
        (400, b"denied".as_slice(), 502, Reading::Caller),
        (
            400,
            br#"{"jsonrpc":"2.0","id":7,"error":{"code":-32001,"message":"PRIVATE missing"}}"#
                .as_slice(),
            502,
            Reading::Caller,
        ),
        (
            401,
            br#"{"jsonrpc":"2.0","id":7,"error":{"code":-32602,"message":"PRIVATE params"}}"#
                .as_slice(),
            502,
            Reading::Hard,
        ),
    ] {
        for addressed in [false, true] {
            let mut relay = task_sent(addressed);
            let reply = answered(&mut relay, status, wire);
            assert_eq!(reply.status, expected, "{status} {wire:?}");
            let got = body(&reply);
            assert_eq!(got["id"], 7);
            assert_eq!(
                got["error"]["code"],
                if expected == 400 { -32602 } else { -32006 }
            );
            assert_eq!(relay.take_reading(), Some(reading));
            assert_eq!(relay.take_reading(), None);
            assert!(!String::from_utf8(reply.body.clone())
                .unwrap()
                .contains("PRIVATE"));
            assert_eq!(relay.take_settled().is_empty(), addressed);
        }
    }
}
