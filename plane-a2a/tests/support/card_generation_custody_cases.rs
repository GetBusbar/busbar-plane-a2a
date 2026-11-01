// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
#[path = "../../src/tests/capture.rs"]
mod capture;
use busbar_contract::abi::mechanism::call::FLAG_RESUME;
use busbar_contract::abi::mechanism::lifecycle::RefreshIn;
use busbar_contract::abi::plane::{PlaneRefreshOut, EMIT_TO_FAR_END};

static PEND_JUDGEMENT: AtomicBool = AtomicBool::new(false);
static PEND_SIGHTING: AtomicBool = AtomicBool::new(false);
static FAIL_SIGHTING: AtomicBool = AtomicBool::new(false);
static DECISIONS: AtomicU64 = AtomicU64::new(0);
static REFRESH_AT_ADMISSION: Mutex<Option<usize>> = Mutex::new(None);
static REFRESH_AT_DECISION: Mutex<Option<usize>> = Mutex::new(None);

pub(super) fn refresh_during_admission() {
    // Release the fixture guard before entering any plugin code.
    let instance = REFRESH_AT_ADMISSION
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take();
    if let Some(instance) = instance {
        let moved = String::from_utf8(SECTION.to_vec())
            .unwrap()
            .replace("/agent", "/replacement");
        refresh(
            &Door {
                instance: instance as *mut c_void,
            },
            2,
            moved.as_bytes(),
        );
    }
}

pub(super) fn pend_judgement() -> bool {
    PEND_JUDGEMENT.swap(false, Ordering::SeqCst)
}

pub(super) fn pend_sighting() -> bool {
    PEND_SIGHTING.swap(false, Ordering::SeqCst)
}

pub(super) fn fail_sighting() -> bool {
    FAIL_SIGHTING.load(Ordering::SeqCst)
}

pub(super) fn note_decision() {
    DECISIONS.fetch_add(1, Ordering::SeqCst);
    let instance = REFRESH_AT_DECISION
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take();
    if let Some(instance) = instance {
        let moved = String::from_utf8(SIGNED_SECTION.to_vec())
            .unwrap()
            .replace("vendor.example", "replacement.example");
        refresh(
            &Door {
                instance: instance as *mut c_void,
            },
            2,
            moved.as_bytes(),
        );
    }
}

struct Reset;
impl Drop for Reset {
    fn drop(&mut self) {
        PEND_JUDGEMENT.store(false, Ordering::SeqCst);
        PEND_SIGHTING.store(false, Ordering::SeqCst);
        FAIL_SIGHTING.store(false, Ordering::SeqCst);
        LIST_PENDS.store(false, Ordering::SeqCst);
        *REFRESH_AT_DECISION
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = None;
        *REFRESH_AT_ADMISSION
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = None;
    }
}

fn refresh(door: &Door, generation: u64, section: &[u8]) {
    let mut input: RefreshIn = z();
    input.head = head::<RefreshIn>(life::REFRESH, Ticket::NONE);
    input.generation = generation;
    input.settings = octets(section);
    let mut output: PlaneRefreshOut = z();
    output.head = out_head::<PlaneRefreshOut>();
    let call = lifecycle().refresh.expect("refresh");
    // SAFETY: the real door receives the ABI's live input/output regions.
    #[allow(unused_unsafe)]
    let result = unsafe {
        call(
            door.instance,
            std::ptr::from_ref(&input).cast(),
            std::ptr::from_mut(&mut output).cast(),
        )
    };
    assert_eq!(result.outcome(), Outcome::Ready);
}

#[test]
fn a_pending_warm_cannot_give_an_old_card_to_a_changed_registration() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let _reset = Reset;
    store().clear();
    handles().clear();
    assert_eq!(open().connect("vendor").1, 200);
    let door = open();
    LIST_PENDS.store(true, Ordering::SeqCst);
    assert_eq!(door.tick().0, Outcome::Pending);
    let moved = String::from_utf8(SECTION.to_vec())
        .unwrap()
        .replace("vendor.example", "replacement.example");
    refresh(&door, 2, moved.as_bytes());
    for _ in 0..4 {
        if door.drive() == Outcome::Ready {
            break;
        }
    }
    assert_eq!(
        door.arrive(
            701,
            ("POST", "/a2a/agents/{agent_id}"),
            "/a2a/agents/vendor",
            CARD_READ
        )
        .0,
        Outcome::Refused,
        "a stored card from the old registration cannot admit the replacement"
    );
}

#[test]
fn a_pending_warm_of_an_unchanged_registration_can_finish_after_refresh() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let _reset = Reset;
    store().clear();
    handles().clear();
    assert_eq!(open().connect("vendor").1, 200);
    let door = open();
    LIST_PENDS.store(true, Ordering::SeqCst);
    assert_eq!(door.tick().0, Outcome::Pending);
    refresh(&door, 2, SECTION);
    for _ in 0..4 {
        if door.drive() == Outcome::Ready {
            break;
        }
    }
    assert_eq!(
        door.arrive(
            702,
            ("POST", "/a2a/agents/{agent_id}"),
            "/a2a/agents/vendor",
            CARD_READ
        )
        .0,
        Outcome::Ready
    );
}

#[test]
fn a_live_unit_keeps_its_card_across_more_than_four_refreshes() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    store().clear();
    let door = open();
    assert_eq!(door.connect("vendor").1, 200);
    assert_eq!(
        door.arrive(
            703,
            ("POST", "/a2a/agents/{agent_id}"),
            "/a2a/agents/vendor",
            CARD_READ
        )
        .0,
        Outcome::Ready
    );
    for generation in 2..=7 {
        refresh(&door, generation, SECTION);
    }
    let answer = door.piece(703, Given::attempt(b"vendor"), 4096);
    assert_ne!(
        answer.flags & EMIT_TO_FAR_END,
        0,
        "the original generation still owns its admitted card: {answer:?}"
    );
}

#[test]
fn an_attempt_cannot_use_a_member_absent_from_the_captured_registration() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    store().clear();
    let door = open();
    assert_eq!(door.connect("vendor").1, 200);
    assert_eq!(
        door.arrive(
            704,
            ("POST", "/a2a/agents/{agent_id}"),
            "/a2a/agents/vendor",
            CARD_READ
        )
        .0,
        Outcome::Ready
    );
    let answer = door.piece(704, Given::attempt(b"unregistered"), 4096);
    assert_eq!(
        answer.flags & EMIT_TO_FAR_END,
        0,
        "an unknown member must not escape the admission guard: {answer:?}"
    );
    assert!(
        !answer.emitted.is_empty(),
        "the caller receives the refusal: {answer:?}"
    );
}

#[test]
fn refresh_during_admission_does_not_replace_the_units_captured_section() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let _reset = Reset;
    store().clear();
    let door = open();
    assert_eq!(door.connect("vendor").1, 200);
    *REFRESH_AT_ADMISSION
        .lock()
        .unwrap_or_else(PoisonError::into_inner) = Some(door.instance as usize);
    assert_eq!(
        door.arrive(
            705,
            ("POST", "/a2a/agents/{agent_id}"),
            "/a2a/agents/vendor",
            CARD_READ
        )
        .0,
        Outcome::Ready
    );
    assert!(REFRESH_AT_ADMISSION
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .is_none());
    let answer = door.piece(705, Given::attempt(b"vendor"), 4096);
    assert_ne!(answer.flags & EMIT_TO_FAR_END, 0, "{answer:?}");
    assert_eq!(
        answer.target, "/agent",
        "the unit must relay through the section it was admitted over"
    );
}

#[test]
fn pending_connect_and_approve_keep_the_original_registration_through_reload() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let _reset = Reset;
    for sighting in [false, true] {
        for approving in [false, true] {
            store().clear();
            let door = open_with(SIGNED_SECTION);
            let preview = door.connect("vendor");
            assert_eq!(preview.1, 200);
            let view: serde_json::Value = serde_json::from_str(&preview.2).unwrap();
            let body = serde_json::to_vec(&serde_json::json!({"fingerprint": view["fingerprint"]}))
                .unwrap();
            let fields = [Field {
                name: str_of(b"content-type"),
                value: str_of(b"application/json"),
            }];
            let route = u32::from(approving);
            let target = if approving {
                "/agents/vendor/approve"
            } else {
                "/agents/vendor/connect"
            };
            DECISIONS.store(0, Ordering::SeqCst);
            if sighting {
                PEND_SIGHTING.store(true, Ordering::SeqCst);
            } else {
                PEND_JUDGEMENT.store(true, Ordering::SeqCst);
            }
            assert_eq!(
                door.verb_audited_flags(route, target, &fields, &body, 0).0,
                Outcome::Pending
            );
            let before = store().clone();
            let moved = String::from_utf8(SIGNED_SECTION.to_vec())
                .unwrap()
                .replace("vendor.example", "replacement.example");
            refresh(&door, 2, moved.as_bytes());
            let result = door.verb_audited_flags(route, target, &fields, &body, FLAG_RESUME);
            assert_eq!(
                (result.0, result.1),
                (Outcome::Ready, 404),
                "sighting={sighting}, approving={approving}: {result:?}"
            );
            assert_eq!(
                *store(),
                before,
                "a stale look writes no replacement card or approval"
            );
            assert_eq!(
                DECISIONS.load(Ordering::SeqCst),
                0,
                "a stale look never approves the replacement"
            );
        }
    }
}

#[test]
fn a_refresh_inside_the_decision_cannot_publish_stale_approval_records() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let _reset = Reset;
    store().clear();
    let door = open_with(SIGNED_SECTION);
    let preview = door.connect("vendor");
    assert_eq!(preview.1, 200);
    let view: serde_json::Value = serde_json::from_str(&preview.2).unwrap();
    let fingerprint = view["fingerprint"].as_str().unwrap();
    let before = store().clone();
    DECISIONS.store(0, Ordering::SeqCst);
    *REFRESH_AT_DECISION
        .lock()
        .unwrap_or_else(PoisonError::into_inner) = Some(door.instance as usize);
    let result = door.approve("vendor", fingerprint);
    assert_eq!((result.0, result.1), (Outcome::Ready, 404), "{result:?}");
    assert_eq!(
        DECISIONS.load(Ordering::SeqCst),
        1,
        "the host crossing actually occurred"
    );
    assert_eq!(
        *store(),
        before,
        "the stale decision publishes no card or approval records"
    );
}

#[test]
fn a_refresh_inside_the_preview_verdict_cannot_publish_stale_card_records() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let _reset = Reset;
    store().clear();
    let door = open();
    assert_eq!(door.connect("vendor").1, 200);
    let before = store().clone();
    *REFRESH_AT_ADMISSION
        .lock()
        .unwrap_or_else(PoisonError::into_inner) = Some(door.instance as usize);
    let result = door.connect("vendor");
    assert_eq!((result.0, result.1), (Outcome::Ready, 404), "{result:?}");
    assert_eq!(*store(), before);
}

/// G1-48: a wake only permits replay. The actual sighting answer must land successfully before
/// the card can be published or approved, even when the trust book's old verdict still serves.
#[test]
fn a_failed_sighting_completion_cannot_publish_or_approve_the_card() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let _reset = Reset;
    for pending in [false, true] {
        for approving in [false, true] {
            FAIL_SIGHTING.store(false, Ordering::SeqCst);
            store().clear();
            let door = open_with(SIGNED_SECTION);
            let body = if approving {
                let preview = door.connect("vendor");
                assert_eq!((preview.0, preview.1), (Outcome::Ready, 200));
                let preview: serde_json::Value = serde_json::from_str(&preview.2).unwrap();
                serde_json::to_vec(&serde_json::json!({"fingerprint": preview["fingerprint"]}))
                    .unwrap()
            } else {
                Vec::new()
            };
            store().clear();
            handles().clear();
            DECISIONS.store(0, Ordering::SeqCst);
            FAIL_SIGHTING.store(true, Ordering::SeqCst);
            PEND_SIGHTING.store(pending, Ordering::SeqCst);
            let fields = [Field {
                name: str_of(b"content-type"),
                value: str_of(b"application/json"),
            }];
            let target = if approving {
                "/agents/vendor/approve"
            } else {
                "/agents/vendor/connect"
            };
            let (sent, heard) = std::sync::mpsc::channel();
            let result = tracing::subscriber::with_default(capture::Capture(sent), || {
                let first =
                    door.verb_audited_flags(u32::from(approving), target, &fields, &body, 0);
                if pending {
                    assert_eq!(first.0, Outcome::Pending);
                    door.verb_audited_flags(
                        u32::from(approving),
                        target,
                        &fields,
                        &body,
                        FLAG_RESUME,
                    )
                } else {
                    first
                }
            });
            assert_eq!(result.0, Outcome::Ready, "{result:?}");
            let sighted: Vec<_> = handles()
                .iter()
                .copied()
                .filter(|(_, op)| *op == service_op::TRUST_SIGHT)
                .collect();
            assert_eq!(
                sighted.len(),
                if pending { 2 } else { 1 },
                "the completion is actually read: {sighted:?}"
            );
            assert!(
                sighted.iter().all(|h| *h == sighted[0]),
                "the original handle is replayed: {sighted:?}"
            );
            assert!(
                store().is_empty(),
                "no card or approval records may escape a failed sighting"
            );
            assert_eq!(DECISIONS.load(Ordering::SeqCst), 0);
            if approving {
                assert_eq!(result.1, 400, "{result:?}");
            } else {
                assert_eq!(result.1, 200, "{result:?}");
                let view: serde_json::Value = serde_json::from_str(&result.2).unwrap();
                assert_eq!(view["state"], "error", "{view}");
                assert!(
                    view["failure"].as_str().unwrap().contains("trust book"),
                    "{view}"
                );
                assert_eq!(
                    door.arrive(
                        750,
                        ("POST", "/a2a/agents/{agent_id}"),
                        "/a2a/agents/vendor",
                        CARD_READ
                    )
                    .0,
                    Outcome::Refused
                );
            }
            let lines: Vec<_> = heard.try_iter().map(|(_, line)| line).collect();
            assert!(
                lines
                    .iter()
                    .any(|l| l.contains("7042") && l.contains("vendor")),
                "{lines:?}"
            );
        }
    }
}

/// G1-48 positive control: a pending sighting that really completes may publish its card.
#[test]
fn a_successful_pending_sighting_reads_its_completion_and_publishes_the_card() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let _reset = Reset;
    store().clear();
    handles().clear();
    let door = open_with(SIGNED_SECTION);
    PEND_SIGHTING.store(true, Ordering::SeqCst);
    assert_eq!(
        door.verb_audited_flags(0, "/agents/vendor/connect", &[], &[], 0)
            .0,
        Outcome::Pending
    );
    let result = door.verb_audited_flags(0, "/agents/vendor/connect", &[], &[], FLAG_RESUME);
    assert_eq!((result.0, result.1), (Outcome::Ready, 200));
    let view: serde_json::Value = serde_json::from_str(&result.2).unwrap();
    assert!(view["failure"].is_null(), "{view}");
    assert!(view["fingerprint"].is_string(), "{view}");
    let sighted: Vec<_> = handles()
        .iter()
        .copied()
        .filter(|(_, op)| *op == service_op::TRUST_SIGHT)
        .collect();
    assert_eq!(sighted.len(), 2, "{sighted:?}");
    assert_eq!(sighted[0], sighted[1]);
    assert!(
        !store().is_empty(),
        "the successfully sighted card is recorded"
    );
}

/// G1-19: both corrupt persisted kinds leave the agent without a restored card and explain why.
#[test]
fn corrupt_warmed_card_and_approval_records_are_named_by_the_real_tick() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let _reset = Reset;
    store().clear();
    store().extend([
        ("card".into(), "vendor".into(), b"{not json".to_vec()),
        ("card_approval".into(), "vendor".into(), b"[1, 2]".to_vec()),
    ]);
    let door = open_with(SIGNED_SECTION);
    let (sent, heard) = std::sync::mpsc::channel();
    let ticked = tracing::subscriber::with_default(capture::Capture(sent), || door.tick());
    assert_eq!(ticked.0, Outcome::Ready);
    let lines: Vec<_> = heard.try_iter().map(|(_, line)| line).collect();
    for kind in ["card", "card_approval"] {
        assert!(
            lines.iter().any(|l| l.contains("7044")
                && l.contains("vendor")
                && l.contains(&format!("kind={kind:?}"))),
            "{kind}: {lines:?}"
        );
    }
    assert_eq!(
        door.arrive(
            751,
            ("POST", "/a2a/agents/{agent_id}"),
            "/a2a/agents/vendor",
            CARD_READ
        )
        .0,
        Outcome::Refused
    );
}
