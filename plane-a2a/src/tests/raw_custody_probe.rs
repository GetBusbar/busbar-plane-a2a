// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Observe initialized owned bytes while their allocation is still borrowed by RawBytes.

use std::cell::RefCell;

pub(crate) const SECRET: &[u8] = b"raw-a2a-custody-canary";

#[derive(Default)]
struct Scope {
    active: bool,
    payloads: Vec<(usize, usize, bool)>,
}

thread_local! { static SCOPE: RefCell<Scope> = RefCell::new(Scope::default()); }

pub(crate) fn before_wipe(bytes: &[u8]) {
    SCOPE.with(|scope| {
        let mut scope = scope.borrow_mut();
        if scope.active && bytes.windows(SECRET.len()).any(|part| part == SECRET) {
            scope
                .payloads
                .push((bytes.as_ptr() as usize, bytes.len(), false));
        }
    });
}

pub(crate) fn after_wipe(bytes: &[u8]) {
    SCOPE.with(|scope| {
        let mut scope = scope.borrow_mut();
        if let Some(payload) = scope
            .payloads
            .iter_mut()
            .rev()
            .find(|payload| !payload.2 && payload.0 == bytes.as_ptr() as usize)
        {
            assert_eq!(payload.1, bytes.len(), "the same initialized owner prefix");
            assert!(
                bytes.iter().all(|byte| *byte == 0),
                "owned raw bytes remain"
            );
            payload.2 = true;
        }
    });
}

pub(crate) struct Probe;

impl Probe {
    pub(crate) fn start() -> Self {
        SCOPE.with(|scope| {
            let mut scope = scope.borrow_mut();
            assert!(!scope.active);
            *scope = Scope {
                active: true,
                ..Default::default()
            };
        });
        Self
    }

    pub(crate) fn checkpoint(&self) {
        SCOPE.with(|scope| {
            let scope = scope.borrow();
            assert!(!scope.payloads.is_empty(), "an actual raw owner retired");
            assert!(
                scope.payloads.iter().all(|payload| payload.2),
                "every observed owner wiped"
            );
        });
    }

    pub(crate) fn retirements(&self) -> usize {
        SCOPE.with(|scope| scope.borrow().payloads.len())
    }
}

impl Drop for Probe {
    fn drop(&mut self) {
        SCOPE.with(|scope| *scope.borrow_mut() = Scope::default());
    }
}

pub(crate) fn assert_wiped(run: impl FnOnce()) {
    let probe = Probe::start();
    run();
    probe.checkpoint();
}

#[test]
fn the_retirement_observer_rejects_an_unchanged_initialized_owner() {
    let _probe = Probe::start();
    let bytes = SECRET.to_vec();
    before_wipe(&bytes);
    assert!(std::panic::catch_unwind(|| after_wipe(&bytes)).is_err());
}
