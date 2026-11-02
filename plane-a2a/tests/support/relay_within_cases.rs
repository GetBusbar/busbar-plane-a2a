// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::abi::host::conn::connector::{
    EGRESS_OPEN_WEB, EGRESS_OPERATOR_INFRASTRUCTURE,
};
use busbar_contract::abi::host::service::DestJudgeIn;
use busbar_contract::abi::mechanism::call::Span;
use std::collections::VecDeque;

const WITHIN: &str = "busbar-dial-within";
type JudgementCall = ((u32, u32, u32), u32, String);

struct Script {
    answers: VecDeque<Vec<&'static str>>,
    pending: bool,
    calls: Vec<JudgementCall>,
}

static SCRIPT: Mutex<Option<Script>> = Mutex::new(None);

struct Scenario;
impl Scenario {
    fn start(answers: &[&[&'static str]], pending: bool) -> Self {
        *SCRIPT.lock().unwrap_or_else(PoisonError::into_inner) = Some(Script {
            answers: answers.iter().map(|answer| answer.to_vec()).collect(),
            pending,
            calls: Vec::new(),
        });
        Self
    }

    fn calls(&self) -> Vec<JudgementCall> {
        SCRIPT
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .unwrap()
            .calls
            .clone()
    }
}

impl Drop for Scenario {
    fn drop(&mut self) {
        *SCRIPT.lock().unwrap_or_else(PoisonError::into_inner) = None;
    }
}

pub(super) fn scripted_judgement(input: *const c_void, out: *mut ServiceOut) -> Option<RawOutcome> {
    let mut script = SCRIPT.lock().unwrap_or_else(PoisonError::into_inner);
    let script = script.as_mut()?;
    // SAFETY: the real SDK lends a DestJudgeIn and its destination for this service call.
    let input = unsafe { input.cast::<DestJudgeIn>().read() };
    let destination = unsafe { std::slice::from_raw_parts(input.dest.ptr(), input.dest.len()) };
    let handle = input.head.handle;
    script.calls.push((
        (handle.ticket.slot, handle.ticket.generation, handle.seq),
        input.egress_class,
        String::from_utf8_lossy(destination).into_owned(),
    ));
    if std::mem::take(&mut script.pending) {
        return Some(answer(out, Outcome::Pending, 0, 0));
    }
    let addresses = if script.answers.len() > 1 {
        script.answers.pop_front().unwrap()
    } else {
        script.answers.front().unwrap().clone()
    };
    // SAFETY: these are the writable byte/span regions the real SDK supplied, at its capacities.
    let (bytes, spans) = unsafe {
        (
            std::slice::from_raw_parts_mut(input.into.buf, input.into.cap),
            std::slice::from_raw_parts_mut(input.into.spans, input.into.spans_cap),
        )
    };
    let mut used = 0;
    for (index, address) in addresses.iter().enumerate() {
        bytes[used..used + address.len()].copy_from_slice(address.as_bytes());
        spans[index] = ItemSpan {
            key: Span {
                offset: used as u32,
                len: address.len() as u32,
            },
            value: Span {
                offset: busbar_contract::abi::mechanism::check::SPAN_ABSENT,
                len: 0,
            },
        };
        used += address.len();
    }
    let result = answer(out, Outcome::Ready, DEST_ALLOWED, used as u64);
    // SAFETY: the SDK's ServiceOut is live; names occupy the spans just written above.
    unsafe {
        (*out).items = addresses.len() as u64;
    }
    Some(result)
}

fn pin(answer: &Answered) -> &str {
    assert_eq!(answer.outcome, Some(Outcome::Ready), "{answer:?}");
    assert_eq!(
        answer.verb, "POST",
        "the answer must be an actual relay head"
    );
    assert_ne!(
        answer.flags & busbar_contract::abi::plane::EMIT_TO_FAR_END,
        0
    );
    let pins: Vec<_> = answer
        .fields
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case(WITHIN))
        .collect();
    assert_eq!(pins.len(), 1, "{answer:?}");
    assert_eq!(
        answer.fields.last().unwrap().0,
        WITHIN,
        "the host control wins over earlier fields"
    );
    &pins[0].1
}

fn arrive(door: &Door, unit: u64) {
    assert_eq!(
        door.arrive(
            unit,
            ("POST", "/a2a/agents/{agent_id}"),
            "/a2a/agents/vendor",
            CARD_READ
        ),
        (Outcome::Ready, 0)
    );
}

#[test]
fn actual_relay_heads_keep_the_judged_set_for_public_and_private_reach() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    const PUBLIC: &[u8] = br#"{"vendor":{"url":"https://vendor.example/agent","pin":{"mechanism":"unpinned"},"reverify_ttl":"1h"}}"#;
    const PRIVATE: &[u8] = br#"{"vendor":{"url":"https://vendor.example/agent","pin":{"mechanism":"unpinned"},"allow_private":true,"reverify_ttl":"1h"}}"#;
    for (section, expected_class, addresses) in [
        (PUBLIC, EGRESS_OPEN_WEB, &["203.0.113.7", "2001:db8::7"][..]),
        (
            PRIVATE,
            EGRESS_OPERATOR_INFRASTRUCTURE,
            &["10.0.0.7", "fd00::7"][..],
        ),
    ] {
        let door = open_with(section);
        let (outcome, status, body) = door.connect("vendor");
        assert_eq!((outcome, status), (Outcome::Ready, 200), "{body}");
        arrive(&door, 500);
        let scenario = Scenario::start(&[addresses], false);
        let answered = door.piece(500, Given::attempt(b"vendor"), 4096);
        assert_eq!(pin(&answered), addresses.join(","));
        let calls = scenario.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].1, expected_class);
        assert_eq!(calls[0].2, "https://vendor.example/agent");
    }
}

#[test]
fn pending_and_short_recall_keep_the_same_pin_then_a_new_attempt_judges_again() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    const SECTION: &[u8] = br#"{"vendor":{"url":"https://vendor.example/agent","pin":{"mechanism":"unpinned"},"reverify_ttl":"1h"}}"#;
    let door = open_with(SECTION);
    let (outcome, status, body) = door.connect("vendor");
    assert_eq!((outcome, status), (Outcome::Ready, 200), "{body}");
    arrive(&door, 501);
    let scenario = Scenario::start(&[&["203.0.113.7"], &["203.0.113.8"]], true);
    let pending = door.piece_with_fields(501, Given::attempt(b"vendor"), 4096, 0);
    assert_eq!(pending.outcome, Some(Outcome::Pending), "{pending:?}");
    let short = door.piece_with_fields(501, Given::attempt(b"vendor"), 4096, 0);
    assert_eq!(short.outcome, Some(Outcome::Failed), "{short:?}");
    assert!(short.fields_needed > 0);
    let re_called = door.piece(501, Given::attempt(b"vendor"), 4096);
    assert_eq!(
        pin(&re_called),
        "203.0.113.7",
        "a resolver change cannot rewrite a short answer"
    );
    let calls = scenario.calls();
    assert_eq!(calls.len(), 2, "short recall must make no new judgement");
    assert_eq!(
        calls[0].0, calls[1].0,
        "PENDING resumes the same completion handle"
    );
    let mut next = Given::attempt(b"vendor");
    next.attempt = 2;
    let next = door.piece(501, next, 4096);
    assert_eq!(pin(&next), "203.0.113.8");
    let calls = scenario.calls();
    assert_eq!(calls.len(), 3);
    assert_ne!(calls[1].0, calls[2].0, "a new attempt owns a new judgement");
}

#[test]
fn changing_the_selected_member_and_url_cannot_reuse_a_previous_relay_pin() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    const SECTION: &[u8] = br#"{"vendor":{"url":"https://vendor.example/agent","pin":{"mechanism":"unpinned"},"reverify_ttl":"1h"},"backup":{"url":"https://vendor.example/other","pin":{"mechanism":"unpinned"},"reverify_ttl":"1h"}}"#;
    let door = open_with(SECTION);
    for member in ["vendor", "backup"] {
        let (outcome, status, body) = door.connect(member);
        assert_eq!((outcome, status), (Outcome::Ready, 200), "{body}");
    }
    arrive(&door, 502);
    let scenario = Scenario::start(&[&["203.0.113.7"], &["203.0.113.9"]], false);
    assert_eq!(
        pin(&door.piece(502, Given::attempt(b"vendor"), 4096)),
        "203.0.113.7"
    );

    let backup = Given::attempt(b"backup");
    let answered = door.piece(502, backup, 4096);
    assert_eq!(pin(&answered), "203.0.113.9");
    assert_eq!(answered.target, "/other");
    let calls = scenario.calls();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].2, "https://vendor.example/agent");
    assert_eq!(calls[1].2, "https://vendor.example/other");
}
