// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A safe witness reads only a borrowed, initialized String while its owner is still alive.

use std::cell::RefCell;

pub(crate) const SECRET: &str = "callback-credential-custody-canary";

#[derive(Default)]
pub(super) struct Scope {
    pub(super) active: bool,
    pub(super) payloads: Vec<(usize, usize, bool)>,
}

thread_local! { pub(super) static SCOPE: RefCell<Scope> = RefCell::new(Scope::default()); }

#[allow(dead_code)]
pub(crate) fn observe(after_wipe: bool, text: &str) {
    SCOPE.with(|scope| {
        let mut scope = scope.borrow_mut();
        if !scope.active {
            return;
        }
        let address = text.as_ptr() as usize;
        if !after_wipe && text == SECRET {
            scope.payloads.push((address, text.len(), false));
        } else if after_wipe {
            if let Some(payload) = scope
                .payloads
                .iter_mut()
                .rev()
                .find(|payload| payload.0 == address && !payload.2)
            {
                assert_eq!(
                    text.len(),
                    payload.1,
                    "the same initialized prefix is observed"
                );
                assert!(
                    text.as_bytes().iter().all(|byte| *byte == 0),
                    "credential was not wiped"
                );
                payload.2 = true;
            }
        }
    });
}

pub(super) struct Probe;
impl Probe {
    pub(super) fn start() -> Self {
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

    pub(super) fn finished(self) {
        SCOPE.with(|scope| {
            let scope = scope.borrow();
            assert!(
                !scope.payloads.is_empty(),
                "the owned credential String was not observed"
            );
            assert!(
                scope.payloads.iter().all(|payload| payload.2),
                "an observed credential escaped wiping"
            );
        });
    }
}
impl Drop for Probe {
    fn drop(&mut self) {
        SCOPE.with(|scope| *scope.borrow_mut() = Scope::default());
    }
}

/// Observe the credential allocations owned and released by one synchronous codec call.
pub(crate) fn assert_wiped(run: impl FnOnce()) {
    let probe = Probe::start();
    run();
    probe.finished();
}
