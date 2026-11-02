// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Test-only seeding of the existing private backend cache; no product helper/API.
use super::*;
use busbar_contract::abi::host::conn::connector::EstablishIn;
use busbar_contract::abi::host::service::{DestJudgeIn, TrustServesIn};
use busbar_contract::abi::sdk::{conn::StaticHost, StaticServices};
use busbar_test_kit::test_support::fake::{self, FakeHost, FakeService, ServiceCall};
use std::cell::Cell;

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
struct Admitted;
impl FakeService for Admitted {
    type In = DestJudgeIn;
    fn serve(call: &mut ServiceCall<Self::In>) -> Outcome {
        call.set_value(busbar_contract::abi::host::service::DEST_ALLOWED);
        Outcome::Ready
    }
}
struct Serving;
impl FakeService for Serving {
    type In = TrustServesIn;
    fn serve(call: &mut ServiceCall<Self::In>) -> Outcome {
        call.set_value(busbar_contract::abi::host::service::DISTRUST_NONE);
        Outcome::Ready
    }
}
struct FailedDial;
impl FakeService for FailedDial {
    type In = EstablishIn;
    fn serve(_: &mut ServiceCall<Self::In>) -> Outcome {
        DIALS.with(|v| v.set(v.get() + 1));
        Outcome::Failed
    }
}

#[test]
fn a_real_failed_mirror_dial_is_visible_without_changing_best_effort_completion() {
    DIALS.with(|v| v.set(0));
    let fake: &'static FakeHost = Box::leak(Box::new(
        FakeHost::new()
            .serve(fake::host::DEST_JUDGE, Admitted)
            .serve(fake::host::TRUST_SERVES, Serving)
            .serve(fake::conn::ESTABLISH, FailedDial),
    ));
    let tables = fake.lent();
    let plane = A2aDoor {
        host: Some(Host::of(tables)),
        services: Services::of(tables),
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
