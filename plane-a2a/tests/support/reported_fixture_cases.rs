// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Reported lifetime and records-host cases, through the existing door and callback APIs.
use super::*;
use busbar_contract::abi::host::service::ServiceBufs;

fn card_answer() -> Vec<u8> {
    let card: serde_json::Value = serde_json::from_slice(CARD).unwrap();
    serde_json::to_vec(&serde_json::json!({"jsonrpc":"2.0", "id":1, "result":card})).unwrap()
}

fn begin_relay(door: &Door, unit: u64) {
    assert_eq!(
        door.arrive(
            unit,
            ("POST", "/a2a/agents/{agent_id}"),
            "/a2a/agents/vendor",
            CARD_READ
        ),
        (Outcome::Ready, 0)
    );
    for piece in [Given::attempt(b"vendor"), Given::caller(CARD_READ)] {
        let answer = door.piece(unit, piece, 1 << 16);
        assert_eq!(answer.outcome, Some(Outcome::Ready), "{answer:?}");
    }
}

#[test]
fn completed_successful_relays_make_room_without_evicting_an_unfinished_answer() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let door = open();
    let (outcome, status, body) = door.connect("vendor");
    assert_eq!((outcome, status), (Outcome::Ready, 200), "{body}");
    door.begin_own_card(1);
    let reply = card_answer();
    for unit in 2..=MAX_UNITS as u64 + 1 {
        begin_relay(&door, unit);
        let answer = door.piece(unit, Given::far_end(200, &reply), 1 << 16);
        assert_eq!(answer.outcome, Some(Outcome::Ready), "{answer:?}");
        assert_ne!(answer.flags & EMIT_DONE, 0, "{answer:?}");
        let body: serde_json::Value = serde_json::from_slice(&answer.emitted).unwrap();
        assert!(body.get("error").is_none(), "{body}");
        assert_eq!(body["result"]["name"], "vendor", "{body}");
    }
    assert!(
        door.still_answers(1),
        "completed relays displaced the live answer"
    );
}

#[test]
fn cancellation_after_a_head_or_unfinished_body_is_partial() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let door = open();
    let (outcome, status, body) = door.connect("vendor");
    assert_eq!((outcome, status), (Outcome::Ready, 200), "{body}");
    begin_relay(&door, 50);
    assert_eq!(door.cancel_disposition(50), CANCEL_ABORTED);
    for (unit, bytes) in [
        (51, b"".as_slice()),
        (52, br#"{"jsonrpc":"2.0","id":1,"result":{"#.as_slice()),
    ] {
        begin_relay(&door, unit);
        let mut given = Given::far_end(200, bytes);
        given.flags = PIECE_HAS_STATUS;
        let answer = door.piece(unit, given, 1 << 16);
        assert_eq!(answer.outcome, Some(Outcome::Ready), "{answer:?}");
        assert_eq!(
            answer.flags & EMIT_DONE,
            0,
            "the reply is not complete: {answer:?}"
        );
        assert_eq!(door.cancel_disposition(unit), CANCEL_OK_PARTIAL);
    }
    begin_relay(&door, 53);
    let answer = door.piece(53, Given::far_end(200, &card_answer()), 1 << 16);
    assert_eq!(answer.outcome, Some(Outcome::Ready), "{answer:?}");
    assert_ne!(answer.flags & EMIT_DONE, 0);
    assert_eq!(door.cancel_disposition(53), CANCEL_OK_PARTIAL);
}

fn list_page(
    prefix: &[u8],
    after: &[u8],
    limit: u32,
    bytes: &mut [u8],
    spans: &mut [ItemSpan],
) -> (Outcome, ServiceOut) {
    let input = RecordsListIn {
        head: ServiceHead {
            size: std::mem::size_of::<RecordsListIn>() as u32,
            op: service_op::RECORDS_LIST,
            ..ServiceHead::ZERO
        },
        kind: str_of(b"fixture"),
        prefix: str_of(prefix),
        after: str_of(after),
        limit,
        _reserved: 0,
        into: ServiceBufs {
            buf: bytes.as_mut_ptr(),
            cap: bytes.len(),
            spans: spans.as_mut_ptr(),
            spans_cap: spans.len(),
        },
    };
    let mut out = ServiceOut::ZERO;
    let result = records_list(HostCtx::NONE, std::ptr::from_ref(&input).cast(), &mut out);
    (result.outcome(), out)
}

fn keys(bytes: &[u8], spans: &[ItemSpan], count: u64) -> Vec<String> {
    spans[..count as usize]
        .iter()
        .map(|s| {
            let start = s.key.offset as usize;
            std::str::from_utf8(&bytes[start..start + s.key.len as usize])
                .unwrap()
                .to_string()
        })
        .collect()
}

#[test]
fn records_host_pages_by_prefix_and_exclusive_cursor() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let mut saved = store();
    let old = std::mem::take(&mut *saved);
    *saved = vec![
        ("fixture".into(), "pre-c".into(), b"c".to_vec()),
        ("fixture".into(), "other".into(), b"x".to_vec()),
        ("fixture".into(), "pre-a".into(), b"a".to_vec()),
        ("fixture".into(), "pre-b".into(), b"b".to_vec()),
    ];
    drop(saved);
    struct Restore(Vec<(String, String, Vec<u8>)>);
    impl Drop for Restore {
        fn drop(&mut self) {
            *store() = std::mem::take(&mut self.0);
        }
    }
    let _restore = Restore(old);
    let mut bytes = [0_u8; 128];
    let mut spans = [ItemSpan::ZERO; 8];
    let (result, first) = list_page(b"pre-", b"", 2, &mut bytes, &mut spans);
    assert_eq!(result, Outcome::Ready);
    assert_eq!(keys(&bytes, &spans, first.items), ["pre-a", "pre-b"]);
    let (result, second) = list_page(b"pre-", b"pre-b", 2, &mut bytes, &mut spans);
    assert_eq!(result, Outcome::Ready);
    assert_eq!(keys(&bytes, &spans, second.items), ["pre-c"]);
    let (result, last) = list_page(b"pre-", b"pre-c", 2, &mut bytes, &mut spans);
    assert_eq!(result, Outcome::Ready);
    assert_eq!(last.items, 0);
}
