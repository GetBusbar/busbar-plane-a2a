// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::tests::capture::Capture;

#[test]
fn grpc_transient_trailers_are_transient_and_auth_and_work_errors_keep_their_readings() {
    for (status, reading) in [
        (2, Reading::Transient),
        (4, Reading::Transient),
        (8, Reading::Transient),
        (13, Reading::Transient),
        (14, Reading::Transient),
        (7, Reading::Hard),
        (16, Reading::Hard),
        (5, Reading::Healthy),
    ] {
        let (mut relay, _, message) = dialled(&submission("SendMessage"), None, false);
        let reply = whole(answer(&mut relay, &[], Some(status)));
        assert_eq!(reply.status, 502);
        assert_eq!(relay.take_reading(), Some(reading), "grpc-status {status}");
        assert_eq!(relay.take_reading(), None);
        assert_eq!(
            relay.moved(),
            (message.len() + crate::framed::MESSAGE_PREFIX) as u64
        );
        assert_eq!(relay.on_piece(far(None, &[], true)), PieceAnswer::Nothing);

        let mut stream = streaming();
        let first = part(stream.on_piece(far(None, &stream_event(pb::TaskState::Working), false)));
        assert!(first.head && !first.last);
        assert_eq!(stream.take_reading(), Some(Reading::Healthy));
        let _ = stream.take_settled();
        let end = part(stream.on_far_fields(&[], Some(status), true));
        assert!(end.last && !end.head);
        assert_eq!(
            stream.take_reading(),
            Some(reading),
            "stream grpc-status {status}"
        );
        assert_eq!(stream.take_settled(), vec![TaskSettled::Failed]);
    }
}

#[test]
fn unreadable_grpc_replies_blame_the_backend_and_retain_http_status_precedence() {
    for (status, wire, reading) in [
        (0, vec![1, 0, 0, 0, 0], Reading::Transient),
        (0, vec![0, 0, 0, 0, 2, 0xff], Reading::Transient),
        (0, vec![0, 0, 0, 0, 2, 0xff, 0xff], Reading::Transient),
        (0, vec![], Reading::Transient),
        (401, b"PRIVATE refused".to_vec(), Reading::Hard),
        (503, b"PRIVATE unavailable".to_vec(), Reading::Transient),
        (404, b"PRIVATE missing".to_vec(), Reading::Caller),
    ] {
        let (mut relay, _, sent) = dialled(&submission("SendMessage"), None, false);
        relay.name_backend("private-agent", URL);
        let (tx, rx) = std::sync::mpsc::channel();
        let reply = tracing::subscriber::with_default(Capture(tx), || {
            assert_eq!(
                relay.on_piece(far(Some(status), &wire, false)),
                PieceAnswer::Nothing
            );
            let PieceAnswer::ToCaller(reply) = relay.on_far_fields(&[], Some(0), true) else {
                panic!("the unreadable backend reply is refused");
            };
            reply
        });
        assert_eq!(reply.status, 502);
        assert_eq!(relay.take_reading(), Some(reading));
        assert_eq!(
            relay.moved(),
            (sent.len() + crate::framed::MESSAGE_PREFIX + wire.len()) as u64
        );
        let text = String::from_utf8(reply.body.clone()).unwrap();
        assert!(
            !text.contains("unframable")
                && !text.contains("PRIVATE")
                && !text.contains("backend.agent.test")
        );
        assert!(
            rx.try_iter()
                .any(|(level, line)| level == tracing::Level::DEBUG
                    && line.contains("backend.agent.test")),
            "the actual backend failure is journaled"
        );
    }
}

#[test]
fn final_ok_grpc_trailers_do_not_hide_a_partial_trailing_message() {
    let next = stream_event(pb::TaskState::Completed);
    for split in [1, 4, 5, next.len() - 1] {
        let mut relay = streaming();
        let initial = stream_event(pb::TaskState::Working);
        let first = part(relay.on_piece(far(None, &initial, false)));
        assert!(first.head && !first.last);
        let _ = relay.take_settled();
        let _ = relay.take_reading();
        let before = relay.moved();
        assert_eq!(
            relay.on_piece(far(None, &next[..split], false)),
            PieceAnswer::Nothing
        );
        let end = part(relay.on_far_fields(&[], Some(0), true));
        assert!(end.last && !end.head);
        assert_eq!(
            relay.take_settled(),
            vec![TaskSettled::Failed],
            "split {split}"
        );
        assert_eq!(relay.take_reading(), Some(Reading::Transient));
        assert_eq!(relay.moved(), before + split as u64);
        assert_eq!(
            relay.on_piece(far(None, &next[split..], true)),
            PieceAnswer::Nothing
        );
    }
}

#[test]
fn a_final_piece_with_a_whole_event_and_a_partial_next_event_keeps_only_the_whole_event() {
    let mut relay = streaming();
    let mut wire = stream_event(pb::TaskState::Working);
    wire.extend_from_slice(&[0, 0, 0]);
    let _ = relay.on_far_fields(&[], Some(0), false);
    let end = part(relay.on_piece(far(None, &wire, true)));
    assert!(end.head && end.last);
    assert_eq!(
        String::from_utf8(end.body.clone())
            .unwrap()
            .matches("data: ")
            .count(),
        1
    );
    assert_eq!(relay.take_settled().last(), Some(&TaskSettled::Failed));
    assert_eq!(relay.take_reading(), Some(Reading::Transient));
}

#[test]
fn split_grpc_messages_completed_before_ok_trailers_keep_the_successful_task_and_bytes() {
    let next = stream_event(pb::TaskState::Completed);
    for split in [1, 4, 5, next.len() - 1] {
        let mut relay = streaming();
        let initial = stream_event(pb::TaskState::Working);
        let _ = relay.on_piece(far(None, &initial, false));
        let _ = relay.take_settled();
        let before = relay.moved();
        assert_eq!(
            relay.on_piece(far(None, &next[..split], false)),
            PieceAnswer::Nothing
        );
        let _ = relay.on_piece(far(None, &next[split..], false));
        let end = part(relay.on_far_fields(&[], Some(0), true));
        assert!(end.last && end.body.is_empty());
        assert_eq!(
            relay.take_settled(),
            vec![TaskSettled::Event {
                state: Some(TaskState::Completed),
                artifact: false,
                backend_id: Some(BACKEND.into())
            }]
        );
        assert_eq!(relay.moved(), before + next.len() as u64);
    }
}
