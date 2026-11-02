// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Refusal windows through the actual A2A door and its existing conditional callback fixture.

use super::*;

const CREATE: &[u8] = br#"{"jsonrpc":"2.0","id":"caller-id","method":"CreateTaskPushNotificationConfig","params":{"taskId":"t1","id":"cfg","url":"https://receiver.example/cb"}}"#;

fn config_windows(door: &Door, unit: u64, body: &[u8], framed: bool, cap: usize) -> Vec<Answered> {
    let (route, target) = if framed {
        (
            "/lf.a2a.v1.A2AService/{method}",
            "/lf.a2a.v1.A2AService/CreateTaskPushNotificationConfig",
        )
    } else {
        ("/a2a/agents/{agent_id}", "/a2a/agents/vendor")
    };
    assert_eq!(
        door.arrive(unit, ("POST", route), target, body).0,
        Outcome::Ready
    );
    let attempt = piece_sized(door, unit, Given::attempt(b"vendor"), 65536, 8, 4096);
    assert_eq!(attempt.outcome, Some(Outcome::Ready), "{attempt:?}");
    let mut given = Given::caller(body);
    let mut outputs = Vec::new();
    for _ in 0..100 {
        let output = piece_sized(door, unit, given, cap, 8, 4096);
        assert_eq!(output.outcome, Some(Outcome::Ready), "{output:?}");
        let finished = output.more == 0;
        outputs.push(output);
        if finished {
            return outputs;
        }
        given = Given {
            flags: 0,
            bytes: &[],
            ..given
        };
    }
    panic!("the fixed config answer did not finish its reply windows");
}

fn prepared() -> (Reset, Door) {
    let (reset, door) = open_scripted();
    assert_eq!(door.connect("vendor").1, 200);
    seed_task("t1", "working");
    (reset, door)
}

#[test]
fn refused_json_and_every_partial_suffix_emit_the_exact_error_without_effects() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let (_reset, door) = prepared();
    script(|s| s.publish_failed = true);
    let outputs = config_windows(&door, 2801, CREATE, false, 8);
    assert!(
        outputs.len() > 1,
        "the reply crosses actual partial windows"
    );
    assert_eq!(outputs[0].reply_status, Some(500));
    assert_eq!(outputs.last().unwrap().flags, EMIT_DONE);
    let body: Vec<u8> = outputs
        .iter()
        .flat_map(|out| out.emitted.iter().copied())
        .collect();
    assert_eq!(
        serde_json::from_slice::<Value>(&body).unwrap(),
        json!({"jsonrpc":"2.0","id":"caller-id","error":{
            "code":-32603,"message":"the push notification config could not be recorded"
        }})
    );
    for out in outputs {
        assert_eq!((out.records_written, out.units_written), (Some(0), Some(0)));
        assert_eq!(out.lane.as_deref(), Some(""));
        assert!(out.verb.is_empty() && out.target.is_empty());
        assert_eq!(out.flags & busbar_contract::abi::plane::EMIT_TO_FAR_END, 0);
        assert_eq!(
            out.need, None,
            "no outbound need is readable without a far request"
        );
        assert_eq!(out.fault, Some(0));
    }
}

#[test]
fn refused_grpc_error_remains_http_200_with_final_status_and_no_effects() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let (_reset, door) = prepared();
    script(|s| s.publish_failed = true);
    // a2a.proto TaskPushNotificationConfig: id=2, task_id=3 and url=4, all strings.
    let url = b"https://receiver.example/cb";
    let mut message = b"\x12\x03cfg\x1a\x02t1".to_vec();
    message.extend_from_slice(&[0x22, url.len() as u8]);
    message.extend_from_slice(url);
    // The gRPC transport removes its five-byte framing before handing the message to ARRIVE.
    let outputs = config_windows(&door, 2802, &message, true, 1024);
    assert_eq!(outputs.len(), 1);
    let out = &outputs[0];
    assert_eq!(out.reply_status, Some(200));
    assert_eq!(
        out.flags,
        EMIT_DONE | busbar_contract::abi::plane::EMIT_FINAL_STATUS
    );
    assert_ne!(
        out.final_status
            .expect("final status is readable under its flag"),
        0
    );
    assert!(out.emitted.is_empty());
    assert_eq!((out.records_written, out.units_written), (Some(0), Some(0)));
    assert_eq!(out.lane.as_deref(), Some(""));
}

#[test]
fn ordinary_observed_response_keeps_its_fee_audit_and_lane() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let (_reset, door) = prepared();
    let outputs = config_windows(&door, 2803, CREATE, false, 1024);
    assert_eq!(outputs.len(), 1);
    assert_eq!(
        (outputs[0].records_written, outputs[0].units_written),
        (Some(1), Some(1))
    );
    assert!(!outputs[0]
        .lane
        .as_ref()
        .expect("Ready lane observation")
        .is_empty());
}
