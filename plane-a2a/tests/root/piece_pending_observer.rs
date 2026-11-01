// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use busbar_contract::abi::mechanism::call::{InHead, Op, Outcome, RawOutcome};
use busbar_contract::abi::mechanism::door::{Door, DoorFn};
use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::abi::plane::{self, OnPieceIn, Ops};

static ACTIVE: Mutex<Option<Arc<Observation>>> = Mutex::new(None);
static ORIGINAL: OnceLock<Op> = OnceLock::new();
static WRAPPED: AtomicPtr<Door> = AtomicPtr::new(std::ptr::null_mut());
static INITIALIZED: OnceLock<()> = OnceLock::new();

#[derive(Default)]
struct Observation {
    owner: AtomicU64,
    armed: AtomicBool,
    waiter: AtomicU64,
}

/// Installed under PUBLISHING; reset even when an assertion unwinds.
pub(super) struct Watching(Arc<Observation>);

impl Watching {
    pub(super) fn install() -> Self {
        let observation = Arc::new(Observation::default());
        let mut active = ACTIVE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(active.is_none(), "one piece observer at a time");
        *active = Some(Arc::clone(&observation));
        Self(observation)
    }

    pub(super) fn arm_after_owner_held(&self) {
        assert_ne!(
            self.0.owner.load(Ordering::SeqCst),
            0,
            "the delayed owner entered an ATTEMPT callback"
        );
        self.0.armed.store(true, Ordering::SeqCst);
    }

    pub(super) fn waiter_pending(&self) -> bool {
        self.0.waiter.load(Ordering::SeqCst) != 0
    }
}

impl Drop for Watching {
    fn drop(&mut self) {
        let mut active = ACTIVE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if active
            .as_ref()
            .is_some_and(|active| Arc::ptr_eq(active, &self.0))
        {
            *active = None;
        }
    }
}

/// Every unobserved fixture receives the real door unchanged.
pub(super) fn select(real: DoorFn) -> DoorFn {
    if ACTIVE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .is_none()
    {
        return real;
    }
    INITIALIZED.get_or_init(|| {
        let real = real();
        let mut parts = real.parts();
        assert_eq!(parts.kind, KindCode::Plane as u32);
        assert_eq!(parts.kind_abi, KindCode::Plane.abi_version());
        assert_eq!(parts.layout, KindCode::Plane.layout_fingerprint());
        assert!(!parts.ops.is_null());
        // SAFETY: the real linked door's ops pointer is live, aligned and static. Read its
        // common head before reading the full table that the matching ABI/layout describes.
        assert!(unsafe { (*parts.ops).slots } >= plane::SLOTS);
        // SAFETY: the linked door states this exact plane layout and enough slots above.
        let mut ops = unsafe { *parts.ops.cast::<Ops>() };
        ORIGINAL
            .set(ops.on_piece.expect("the real plane implements on_piece"))
            .expect("one original op");
        ops.on_piece = Some(on_piece);
        // The immutable copied table is process-lived; every other callback remains real.
        parts.ops = &Box::leak(Box::new(ops)).head;
        // SAFETY: the static real Statement/slots are preserved, except for an on_piece
        // trampoline obeying the same ABI. The copied table is leaked for the door's lifetime.
        let wrapped = unsafe { Door::__from_parts(parts).__with_migrate(real.migrate()) };
        WRAPPED.store(Box::into_raw(Box::new(wrapped)), Ordering::SeqCst);
    });
    observed_door
}

extern "C" fn observed_door() -> &'static Door {
    // SAFETY: select initialized this non-null immutable Box before returning this function.
    // It is never freed and borrows nothing from an active observation.
    unsafe { &*WRAPPED.load(Ordering::SeqCst) }
}

extern "C" fn on_piece(
    instance: *mut c_void,
    input: *const c_void,
    out: *mut c_void,
) -> RawOutcome {
    let observation = ACTIVE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    let piece = if !input.is_null() {
        // SAFETY: on_piece's host input is a live InHead-prefixed frame for this whole call.
        // Copy the full frame only when its stated size covers it; no borrowed pointer escapes.
        let head = unsafe { std::ptr::read_unaligned(input.cast::<InHead>()) };
        (head.size as usize >= std::mem::size_of::<OnPieceIn>() && head.op == plane::slot::ON_PIECE)
            .then(|| unsafe { std::ptr::read_unaligned(input.cast::<OnPieceIn>()) })
    } else {
        None
    };
    let attempt = piece.filter(|piece| {
        piece.from == plane::FROM_KERNEL && piece.flags & plane::PIECE_REFUSED == 0
    });
    if let (Some(observation), Some(piece)) = (&observation, &attempt) {
        let _ =
            observation
                .owner
                .compare_exchange(0, piece.unit, Ordering::SeqCst, Ordering::SeqCst);
    }
    let Some(original) = ORIGINAL.get() else {
        return RawOutcome(Outcome::Fault as u8);
    };
    // Delegate exactly once with the original pointers; the actual return is authoritative.
    let outcome = original(instance, input, out);
    if outcome.0 == Outcome::Pending as u8 {
        if let (Some(observation), Some(piece)) = (&observation, &attempt) {
            if observation.armed.load(Ordering::SeqCst)
                && piece.unit != observation.owner.load(Ordering::SeqCst)
            {
                let _ = observation.waiter.compare_exchange(
                    0,
                    piece.unit,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                );
            }
        }
    }
    outcome
}
