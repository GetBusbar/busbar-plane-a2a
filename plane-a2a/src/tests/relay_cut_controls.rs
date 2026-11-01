// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[test]
fn a_cut_accounts_payload_once_and_preserves_complete_events_before_its_error() {
    for committed in [false, true] {
        let (mut relay, _) = events_sent();
        let event =
            event(json!({"kind":"status-update","taskId":"backend","status":{"state":"working"}}));
        let (cut_bytes, expected_head) = if committed {
            assert!(part(relay.on_piece(far(Some(200), &event, false))).head);
            let _ = relay.take_settled();
            (&[][..], false)
        } else {
            (event.as_slice(), true)
        };
        let end = part(relay.on_far_cut(cut_bytes, Some(200)));
        assert!(end.last);
        assert_eq!(end.head, expected_head);
        let events = datas(&end.body);
        assert_eq!(events.last().unwrap()["error"]["code"], -32006);
        if !committed {
            assert_eq!(events[0]["result"]["taskId"], task(false).task_id);
        }
        assert_eq!(relay.take_settled().last(), Some(&TaskSettled::Failed));
        assert_eq!(relay.take_reading(), Some(Reading::Transient));
        assert_eq!(relay.take_reading(), None);
        assert_eq!(relay.moved(), (STREAM.len() + event.len()) as u64);
        assert_eq!(relay.on_far_cut(b"late", None), PieceAnswer::Nothing);
        assert_eq!(relay.moved(), (STREAM.len() + event.len()) as u64);
    }
}

#[test]
fn a_cut_whole_answer_is_refused_even_when_its_json_was_complete() {
    let mut relay = task_sent(false);
    let complete = br#"{"jsonrpc":"2.0","id":7,"result":{"kind":"task","id":"backend","status":{"state":"completed"}}}"#;
    let PieceAnswer::ToCaller(reply) = relay.on_far_cut(complete, Some(200)) else {
        panic!("a cut whole answer must be refused");
    };
    assert_eq!(reply.status, 502);
    assert_eq!(relay.take_settled(), vec![TaskSettled::Failed]);
    assert_eq!(relay.take_reading(), Some(Reading::Transient));
    assert_eq!(relay.moved(), (SEND.len() + complete.len()) as u64);
}

#[test]
fn a_cut_non_success_head_never_becomes_a_successful_event_stream() {
    let (mut relay, _) = events_sent();
    let event = event(json!({"kind":"status-update","status":{"state":"working"}}));
    let PieceAnswer::ToCaller(reply) = relay.on_far_cut(&event, Some(401)) else {
        panic!("an unsuccessful HTTP head cannot start the caller's event stream");
    };
    assert_eq!(reply.status, 502);
    assert_eq!(relay.take_reading(), Some(Reading::Hard));
    assert_eq!(relay.take_settled(), vec![TaskSettled::Failed]);
}
