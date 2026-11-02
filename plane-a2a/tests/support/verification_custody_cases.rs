// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::abi::plane::EMIT_TO_FAR_END;

static FAIL_CLOCK: AtomicBool = AtomicBool::new(false);
static PEND_SIGHTING: AtomicU64 = AtomicU64::new(0);
static RECORD_WAKES: AtomicBool = AtomicBool::new(false);
static WOKEN: Mutex<Vec<Ticket>> = Mutex::new(Vec::new());
static APPROVE_AT_VERDICT: Mutex<Option<(usize, String)>> = Mutex::new(None);
static APPROVED: Mutex<Option<(Outcome, u32, String)>> = Mutex::new(None);

pub(super) fn clock_refuses(ticket: Ticket) -> bool {
    assert!(
        ticket.is_none(),
        "clock.now is a synchronous no-ticket service"
    );
    FAIL_CLOCK.load(Ordering::SeqCst)
}

pub(super) fn pend_sighting(input: *const c_void) -> bool {
    // SAFETY: the real service receives the live ABI input beginning with ServiceHead.
    let head = unsafe { input.cast::<ServiceHead>().read() };
    let slot = u64::from(head.handle.ticket.slot);
    slot != 0
        && PEND_SIGHTING
            .compare_exchange(slot, 0, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
}

pub(super) extern "C" fn wake(_: HostCtx, ticket: Ticket) {
    if RECORD_WAKES.load(Ordering::SeqCst) {
        WOKEN
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(ticket);
    }
}

pub(super) fn during_verdict() {
    let approval = APPROVE_AT_VERDICT
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take();
    if let Some((instance, fingerprint)) = approval {
        let result = Door::borrowed(instance as *mut c_void).approve("vendor", &fingerprint);
        *APPROVED.lock().unwrap_or_else(PoisonError::into_inner) = Some(result);
    }
}

struct Reset;

impl Drop for Reset {
    fn drop(&mut self) {
        FAIL_CLOCK.store(false, Ordering::SeqCst);
        PEND_SIGHTING.store(0, Ordering::SeqCst);
        RECORD_WAKES.store(false, Ordering::SeqCst);
        WOKEN.lock().unwrap_or_else(PoisonError::into_inner).clear();
        *APPROVE_AT_VERDICT
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = None;
        *APPROVED.lock().unwrap_or_else(PoisonError::into_inner) = None;
    }
}

fn arrive(door: &Door, unit: u64) {
    assert_eq!(
        door.arrive(
            unit,
            ("POST", "/a2a/agents/{agent_id}"),
            "/a2a/agents/vendor",
            CARD_READ,
        )
        .0,
        Outcome::Ready
    );
}

#[test]
fn pending_piece_retains_its_frames_and_loans_and_rejects_replacement_inputs() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let _reset = Reset;
    store().clear();
    let door = open_with(SIGNED_SECTION);
    assert_eq!(door.connect("vendor").1, 200);
    arrive(&door, 780);
    PEND_SIGHTING.store(780, Ordering::SeqCst);
    let given = Given::attempt(b"vendor");
    assert_eq!(door.piece(780, given, 4096).outcome, Some(Outcome::Pending));
    let loans = || {
        let pending = door.pending.borrow();
        let frame = pending.get(&ticket(780)).unwrap();
        [
            std::ptr::from_ref(&*frame.input) as usize,
            std::ptr::from_ref(&*frame.output) as usize,
            frame.input.member.ptr() as usize,
            frame.input.bytes.ptr as usize,
            frame.input.reply_buf as usize,
            frame.input.fields_buf as usize,
            frame.input.records_buf as usize,
            frame.input.units_buf as usize,
            frame.input.arena_buf as usize,
        ]
    };
    let original = loans();
    let mut changed = given;
    changed.attempt += 1;
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        door.piece(780, changed, 4096)
    }))
    .is_err());
    assert_eq!(
        loans(),
        original,
        "a rejected input retains the original loans"
    );
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        door.piece(780, given, 8192)
    }))
    .is_err());
    assert_eq!(
        loans(),
        original,
        "Pending cannot replace the output allocation"
    );
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| { arrive(&door, 780) })).is_err()
    );
    assert_eq!(
        loans(),
        original,
        "a fresh arrival cannot erase the continuation"
    );
    let resumed = door.piece(780, given, 4096);
    assert_eq!(resumed.outcome, Some(Outcome::Ready));
    assert_ne!(resumed.flags & EMIT_TO_FAR_END, 0);
    assert!(door.pending.borrow().is_empty());
}

#[test]
fn definitive_cancel_retires_pending_loans_and_borrowed_wrappers_do_not_close_the_owner() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let _reset = Reset;
    store().clear();
    let door = open_with(SIGNED_SECTION);
    drop(Door::borrowed(door.instance));
    assert_eq!(
        door.connect("vendor").1,
        200,
        "the borrowed wrapper did not close it"
    );
    arrive(&door, 781);
    PEND_SIGHTING.store(781, Ordering::SeqCst);
    assert_eq!(
        door.piece(781, Given::attempt(b"vendor"), 4096).outcome,
        Some(Outcome::Pending)
    );
    assert_eq!(door.pending.borrow().len(), 1);
    assert_eq!(door.cancel_unit(781), Outcome::Ready);
    assert!(door.pending.borrow().is_empty());
    arrive(&door, 782);
    PEND_SIGHTING.store(782, Ordering::SeqCst);
    assert_eq!(
        door.piece(782, Given::attempt(b"vendor"), 4096).outcome,
        Some(Outcome::Pending)
    );
    assert_eq!(door.pending.borrow().len(), 1);
    // Owned Drop crosses real CLOSE before these unresolved loans are wiped and freed.
    drop(door);
}

#[test]
fn an_unreadable_clock_releases_the_holder_and_removes_refused_waiters() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let _reset = Reset;

    for fail_clock in [false, true] {
        store().clear();
        let door = open_with(SIGNED_SECTION);
        assert_eq!(door.connect("vendor").1, 200);
        for unit in [760, 761, 762] {
            arrive(&door, unit);
        }
        handles().clear();
        WOKEN.lock().unwrap_or_else(PoisonError::into_inner).clear();
        RECORD_WAKES.store(true, Ordering::SeqCst);
        PEND_SIGHTING.store(760, Ordering::SeqCst);
        for unit in [760, 761, 762] {
            let pending = door.piece(unit, Given::attempt(b"vendor"), 4096);
            assert_eq!(pending.outcome, Some(Outcome::Pending), "{pending:?}");
        }
        if fail_clock {
            FAIL_CLOCK.store(true, Ordering::SeqCst);
            let refused = door.piece(761, Given::attempt(b"vendor"), 4096);
            assert_eq!(refused.outcome, Some(Outcome::Ready), "{refused:?}");
            assert_eq!(refused.flags & EMIT_TO_FAR_END, 0, "{refused:?}");
            assert!(!refused.emitted.is_empty(), "{refused:?}");
            assert!(WOKEN
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .is_empty());
            FAIL_CLOCK.store(true, Ordering::SeqCst);
        }
        let holder = door.piece(760, Given::attempt(b"vendor"), 4096);
        assert_eq!(holder.outcome, Some(Outcome::Ready), "{holder:?}");
        assert_eq!(
            holder.flags & EMIT_TO_FAR_END != 0,
            !fail_clock,
            "{holder:?}"
        );
        FAIL_CLOCK.store(false, Ordering::SeqCst);
        let expected = if fail_clock {
            vec![ticket(762)]
        } else {
            vec![ticket(761), ticket(762)]
        };
        assert_eq!(
            *WOKEN.lock().unwrap_or_else(PoisonError::into_inner),
            expected,
            "a refused holder must release its surviving waiter without a CANCEL"
        );
        let waiter = door.piece(762, Given::attempt(b"vendor"), 4096);
        assert_eq!(waiter.outcome, Some(Outcome::Ready), "{waiter:?}");
        assert_ne!(waiter.flags & EMIT_TO_FAR_END, 0, "{waiter:?}");
        let own_looks = handles()
            .iter()
            .filter(|((slot, _, _), op)| *slot == 762 && *op == service_op::TRUST_SIGHT)
            .count();
        assert_eq!(
            own_looks,
            usize::from(fail_clock),
            "only an abandoned look is retried"
        );
    }
}

#[test]
fn an_approval_during_the_verification_verdict_keeps_its_approved_skills() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let _reset = Reset;
    store().clear();
    let door = open_with(SIGNED_SECTION);
    let preview = door.connect("vendor");
    assert_eq!((preview.0, preview.1), (Outcome::Ready, 200));
    let preview: serde_json::Value = serde_json::from_str(&preview.2).unwrap();
    assert_eq!(preview["added"], serde_json::json!(["quote"]));
    let fingerprint = preview["fingerprint"].as_str().unwrap().to_string();
    arrive(&door, 763);
    PEND_SIGHTING.store(763, Ordering::SeqCst);
    let pending = door.piece(763, Given::attempt(b"vendor"), 4096);
    assert_eq!(pending.outcome, Some(Outcome::Pending), "{pending:?}");
    *APPROVE_AT_VERDICT
        .lock()
        .unwrap_or_else(PoisonError::into_inner) = Some((door.instance as usize, fingerprint));
    let sent = door.piece(763, Given::attempt(b"vendor"), 4096);
    assert_eq!(sent.outcome, Some(Outcome::Ready), "{sent:?}");
    assert_ne!(sent.flags & EMIT_TO_FAR_END, 0, "{sent:?}");
    let approved = APPROVED
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take()
        .unwrap();
    assert_eq!(
        (approved.0, approved.1),
        (Outcome::Ready, 200),
        "{approved:?}"
    );
    let approved: serde_json::Value = serde_json::from_str(&approved.2).unwrap();
    assert_eq!(approved["added"], serde_json::json!([]));
    let current = door.connect("vendor");
    assert_eq!((current.0, current.1), (Outcome::Ready, 200));
    let current: serde_json::Value = serde_json::from_str(&current.2).unwrap();
    assert_eq!(
        current["added"],
        serde_json::json!([]),
        "the verification cannot erase a completed approval: {current}"
    );
    assert_eq!(current["changed"], serde_json::json!([]));
    assert_eq!(current["removed"], serde_json::json!([]));
}
