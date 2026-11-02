// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Test-only seeding of the existing private backend cache; no product helper/API.
use super::*;
use busbar_contract::abi::host::conn::connector::ConnectorSlots;
use busbar_contract::abi::host::service::{HostSlots, ServiceOut};
use busbar_contract::abi::mechanism::call::RawOutcome;
use busbar_contract::abi::mechanism::ticket::{HostCtx, HostTables};
use busbar_contract::abi::sdk::test_support::zeroed;
use busbar_contract::abi::sdk::{conn::StaticHost, StaticServices};
use std::cell::Cell;
use std::ffi::c_void;

impl A2aDoor {
    pub(crate) fn listing_lifecycle_fixture(host: StaticHost, services: StaticServices) -> Self {
        let plane = A2aDoor {
            host: Some(host),
            services: Some(services),
            public_url: Some("https://gw.example".into()),
            ..A2aDoor::default()
        };
        let section = std::sync::Arc::new(agents_section(br#"{"planner":{"url":"https://agent.example/a2a","pin":{"mechanism":"unpinned"}}}"#).unwrap());
        let disposition = AgentDisposition::Request {
            row: crate::ops::row_for("ListTasks").unwrap(),
            id: json!(7),
            version: "1.0",
        };
        let mut unit = AgentUnit::new(disposition, None, Some(section), 0);
        unit.ticket = Ticket {
            slot: 3,
            generation: 7,
        };
        plane.units.insert(1, unit);
        plane.cards.hold(
            "planner",
            0,
            json!({"url":"https://agent.example/a2a","preferredTransport":"JSONRPC"}),
        );
        for id in ["t1", "t2"] {
            plane.backends.record(
                MAX_BACKEND_IDS,
                task_key("a11ce", id),
                format!("backend-{id}"),
            );
            plane.tokens.mint("a11ce", id, b"signature").unwrap();
        }
        plane
    }
}

thread_local! { static DIALS: Cell<usize> = const { Cell::new(0) }; }
#[allow(unsafe_code)]
extern "C" fn admitted(_: HostCtx, _: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    let raw = RawOutcome::of(Outcome::Ready);
    // SAFETY: the actual SDK lends this exclusive complete ServiceOut for the callback.
    unsafe {
        out.write(ServiceOut {
            size: std::mem::size_of::<ServiceOut>() as u32,
            outcome: raw,
            value: busbar_contract::abi::host::service::DEST_ALLOWED,
            ..ServiceOut::ZERO
        });
    }
    raw
}

#[allow(unsafe_code)]
extern "C" fn serving(_: HostCtx, _: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    let raw = RawOutcome::of(Outcome::Ready);
    // SAFETY: the actual SDK lends this exclusive complete ServiceOut for the callback.
    unsafe {
        out.write(ServiceOut {
            size: std::mem::size_of::<ServiceOut>() as u32,
            outcome: raw,
            value: busbar_contract::abi::host::service::DISTRUST_NONE,
            ..ServiceOut::ZERO
        });
    }
    raw
}

#[allow(unsafe_code)]
extern "C" fn failed_dial(_: HostCtx, _: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    DIALS.with(|v| v.set(v.get() + 1));
    let raw = RawOutcome::of(Outcome::Failed);
    // SAFETY: the actual SDK lends this exclusive complete ServiceOut for the callback.
    unsafe {
        out.write(ServiceOut {
            size: std::mem::size_of::<ServiceOut>() as u32,
            outcome: raw,
            value: 0,
            ..ServiceOut::ZERO
        });
    }
    raw
}

#[test]
#[allow(unsafe_code)]
fn a_real_failed_mirror_dial_is_visible_without_changing_best_effort_completion() {
    DIALS.with(|v| v.set(0));
    let slots = HostSlots {
        size: std::mem::size_of::<HostSlots>() as u32,
        slots: busbar_contract::abi::host::service::SERVICES,
        dest_judge: Some(admitted),
        trust_serves: Some(serving),
        ..zeroed()
    };
    let conns = ConnectorSlots {
        size: std::mem::size_of::<ConnectorSlots>() as u32,
        slots: busbar_contract::abi::host::conn::connector::SERVICES,
        establish: Some(failed_dial),
        ..zeroed()
    };
    let tables = HostTables {
        size: std::mem::size_of::<HostTables>() as u32,
        _reserved: 0,
        ctx: HostCtx { handle: 1 },
        wake: None,
        conns: &conns,
        services: &slots,
        io: std::ptr::null(),
    };
    // SAFETY: the immutable tables/slot arrays remain live until plane and its mirror call
    // finish; all callbacks are static functions, and no pointer escapes the test.
    let loan = unsafe { busbar_contract::abi::sdk::test_support::lend(&tables) };
    let plane = A2aDoor {
        host: Some(Host::of(loan)),
        services: Services::of(loan),
        ..A2aDoor::default()
    };
    let mut flight = crate::mirror::Flight {
        stage: crate::mirror::Stage::Mirror,
        method: crate::mirror::method::CREATE_PUSH_CONFIG,
        backend_task: "b-1".into(),
        create: json!({}),
        hop: crate::mirror::Originated {
            agent: "planner".into(),
            url: "https://agent.example/a2a".into(),
            allow_private: false,
            binding: crate::binding::Binding::JsonRpc,
            version: "1.0",
            seq: 0,
            exchange: None,
        },
    };
    let (send, receive) = std::sync::mpsc::channel();
    let result = tracing::subscriber::with_default(crate::tests::capture::Capture(send), || {
        drive_mirror(
            &plane,
            Ticket {
                slot: 3,
                generation: 7,
            },
            &mut flight,
        )
    });
    assert!(result.is_ready());
    assert_eq!(flight.stage, crate::mirror::Stage::Done);
    DIALS.with(|v| assert_eq!(v.get(), 1));
    let events: Vec<_> = receive.try_iter().collect();
    assert!(
        events
            .iter()
            .any(|(level, words)| *level == tracing::Level::WARN
                && words.contains("planner")
                && words.contains("transport")
                && words.contains("connector")),
        "{events:?}"
    );
    assert!(!events
        .iter()
        .any(|(_, words)| words.contains("https://") || words.contains("authentication")));
}
