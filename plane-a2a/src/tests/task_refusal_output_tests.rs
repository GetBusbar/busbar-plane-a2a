// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::abi::mechanism::call::{InHead, OutHead};
use busbar_contract::abi::mechanism::lifecycle::{
    slot as life, GenIn, RefreshIn, ReleaseIn, TickIn, TickOut, ValidateIn,
};
use busbar_contract::abi::plane::{
    PlaneCancelIn, PlaneCancelOut, PlaneDriveIn, PlaneDriveOut, PlaneOpenIn, PlaneOpenOut,
    PlaneRefreshOut,
};
use busbar_contract::abi::sdk::{Safe, SafeSlot};
use busbar_test_kit::test_support::{fake::FakeHost, reply, test_in::TestIn, zeroed, DoorView};

const TICKET: Ticket = Ticket {
    slot: 24,
    generation: 5,
};

mod probe {
    use super::*;

    macro_rules! quiet {
        ($name:ident, $input:ty, $output:ty) => {
            pub struct $name;
            impl SafeSlot for $name {
                type In = $input;
                type Out = $output;
                type State = A2aDoor;
                fn call(
                    _: Instance<'_, A2aDoor>,
                    _: Lent<'_, Self::In>,
                    _: Out<'_, Self::Out>,
                ) -> Outcome {
                    Outcome::Ready
                }
            }
        };
    }
    quiet!(Validate, ValidateIn, OutHead);
    quiet!(Refresh, RefreshIn, PlaneRefreshOut);
    quiet!(Retire, GenIn, OutHead);
    quiet!(Tick, TickIn, TickOut);
    quiet!(Drive, PlaneDriveIn, PlaneDriveOut);
    quiet!(Cancel, PlaneCancelIn, PlaneCancelOut);
    quiet!(Release, ReleaseIn, OutHead);
    quiet!(Close, InHead, OutHead);

    pub struct Open;
    impl SafeSlot for Open {
        type In = PlaneOpenIn;
        type Out = PlaneOpenOut;
        type State = A2aDoor;
        fn call(
            instance: Instance<'_, A2aDoor>,
            input: Lent<'_, PlaneOpenIn>,
            _: Out<'_, PlaneOpenOut>,
        ) -> Outcome {
            let tables = input.open().host().unwrap();
            let plane = A2aDoor::listing_lifecycle_fixture(
                busbar_contract::abi::sdk::conn::Host::of(tables),
                Services::of(tables).unwrap(),
            );
            plane.on_unit(1, |u| {
                u.pass.served = true;
                u.pass.audit = Some(("agent:planner".into(), true));
                u.pass.response_only = input.open().settings().bytes() == b"refused";
            });
            instance.open(plane);
            Outcome::Ready
        }
    }

    pub struct Piece;
    impl SafeSlot for Piece {
        type In = OnPieceIn;
        type Out = OnPieceOut;
        type State = A2aDoor;
        fn call(
            instance: Instance<'_, A2aDoor>,
            input: Lent<'_, OnPieceIn>,
            mut out: Out<'_, OnPieceOut>,
        ) -> Outcome {
            let plane = instance.get().unwrap();
            let answer = local::unrecorded_answer(
                LocalVerb::CreatePushConfig(local::Dialect::V10),
                &serde_json::json!("caller-id"),
            )
            .unwrap();
            if input.attempt_no() == 1 {
                return framed_window(
                    plane,
                    1,
                    &input,
                    &mut out,
                    &crate::framed::framed_reply(
                        crate::framed::Rpc::CreateTaskPushNotificationConfig,
                        answer.status,
                        &answer.body,
                    ),
                    &[],
                );
            }
            let writes = if input.attempt_no() == 2 {
                vec![Write {
                    kind: crate::records::KIND_TASK,
                    key: "caller/task".into(),
                    value: b"must not disappear".to_vec(),
                }]
            } else {
                Vec::new()
            };
            let suffix = plane.units.with(&1, |u| {
                u.map(|u| std::mem::take(&mut u.pass.rest))
                    .unwrap_or_default()
            });
            if suffix.is_empty() {
                window(
                    plane,
                    1,
                    &input,
                    &mut out,
                    (answer.status, &answer.body),
                    &writes,
                )
            } else {
                window(plane, 1, &input, &mut out, (0, &suffix), &writes)
            }
        }
    }
    busbar_contract::plugin_door! {
        ops: busbar_contract::abi::plane::Ops,
        statement: busbar_contract::abi::sdk::door::statement("refusal-window-probe", "0", 1),
        lifecycle: {
            validate: Safe<Validate>, open: Safe<Open>, refresh: Safe<Refresh>,
            retire: Safe<Retire>, tick: Safe<Tick>, drive: Safe<Drive>,
            cancel: Safe<Cancel>, release: Safe<Release>, close: Safe<Close>,
        },
        kind_ops: { on_piece: Safe<Piece> },
    }
}

fn windows(
    refused: bool,
    mode: u32,
    capacity: usize,
) -> (Outcome, Vec<reply::PieceOutput>, Vec<u8>) {
    let fake = FakeHost::new();
    let view = DoorView::of(probe::MACRO_DOOR);
    let settings = if refused {
        b"refused".as_slice()
    } else {
        b"observed".as_slice()
    };
    let open = fake.lend_in(
        TestIn::<PlaneOpenIn>::new()
            .set(|i| &i.open.head.op, life::OPEN)
            .settings(settings),
    );
    let mut opened = reply::call_hosted_in(
        view.op::<busbar_contract::abi::plane::Ops>(|t| &t.head.open)
            .unwrap(),
        None,
        &open,
        zeroed::<PlaneOpenOut>(),
    );
    assert_eq!(opened.outcome, Outcome::Ready, "{opened:?}");
    let instance = opened.take_instance().unwrap();
    let mut outputs = Vec::new();
    let mut body = Vec::new();
    let mut outcome = Outcome::Failed;
    for _ in 0..100 {
        let mut bytes = vec![0; capacity];
        let mut fields = [zeroed::<OutField>(); 8];
        let mut records = [zeroed::<RecordWrite>(); 8];
        let mut units = [zeroed::<UnitCount>(); 8];
        let mut arena = vec![0; 4096];
        let input = TestIn::<OnPieceIn>::new()
            .set(|i| &i.head.op, busbar_contract::abi::plane::slot::ON_PIECE)
            .set(|i| &i.head.ticket, TICKET)
            .set(|i| &i.unit, 1)
            .set(|i| &i.attempt_no, mode)
            .buffer(|i| &i.reply_buf, |i| &i.reply_cap, &mut bytes)
            .buffer(|i| &i.fields_buf, |i| &i.fields_cap, &mut fields)
            .buffer(|i| &i.records_buf, |i| &i.records_cap, &mut records)
            .buffer(|i| &i.units_buf, |i| &i.units_cap, &mut units)
            .buffer(|i| &i.arena_buf, |i| &i.arena_cap, &mut arena);
        let answer = reply::call_piece_in(
            view.op::<busbar_contract::abi::plane::Ops>(|t| &t.on_piece)
                .unwrap(),
            Some(&instance),
            &input,
        );
        outcome = answer.outcome;
        let output = answer.out;
        let emitted = output.emitted as usize;
        let finished = outcome != Outcome::Ready || output.more == 0;
        outputs.push(output);
        drop(input);
        body.extend_from_slice(&bytes[..emitted]);
        if finished {
            break;
        }
    }
    let closed = reply::close_in(
        view.op::<busbar_contract::abi::plane::Ops>(|t| &t.head.close)
            .unwrap(),
        instance,
        &TestIn::<InHead>::new().set(|i| &i.op, life::CLOSE),
        zeroed::<OutHead>(),
    );
    assert_eq!(closed.outcome, Outcome::Ready);
    (outcome, outputs, body)
}

#[test]
fn refused_json_and_every_partial_suffix_emit_the_exact_error_without_effects() {
    let (outcome, outputs, body) = windows(true, 0, 8);
    assert_eq!(outcome, Outcome::Ready);
    assert!(
        outputs.len() > 1,
        "the reply crosses actual partial windows"
    );
    assert_eq!(outputs[0].reply_status, 500);
    assert_eq!(outputs.last().unwrap().flags, EMIT_DONE);
    assert_eq!(
        serde_json::from_slice::<Value>(&body).unwrap(),
        serde_json::json!({
            "jsonrpc":"2.0", "id":"caller-id", "error": {
                "code":-32603, "message":local::CONFIG_UNRECORDED,
            },
        })
    );
    for out in outputs {
        assert_eq!(
            (out.records_written, out.units_written, out.lane.len),
            (0, 0, 0)
        );
        assert_eq!(
            (out.verb.len, out.target.len, out.need, out.fault),
            (0, 0, 0, 0)
        );
    }
}

#[test]
fn refused_grpc_error_remains_http_200_with_final_status_and_no_effects() {
    let (outcome, outputs, body) = windows(true, 1, 1024);
    assert_eq!(outcome, Outcome::Ready);
    assert_eq!(outputs.len(), 1);
    let out = &outputs[0];
    assert_eq!(out.reply_status, 200);
    assert_eq!(
        out.flags,
        EMIT_DONE | busbar_contract::abi::plane::EMIT_FINAL_STATUS
    );
    assert_ne!(out.final_status, 0);
    assert!(body.is_empty());
    assert_eq!(
        (out.records_written, out.units_written, out.lane.len),
        (0, 0, 0)
    );
}

#[test]
fn refused_output_rejects_staged_writes_instead_of_discarding_them() {
    let pass = Pass {
        served: true,
        audit: Some(("agent:planner".into(), true)),
        response_only: true,
        ..Pass::default()
    };
    let writes = [Write {
        kind: crate::records::KIND_TASK,
        key: "caller/task".into(),
        value: b"must not disappear".to_vec(),
    }];
    assert_eq!(
        check_response_effects(pass.response_only, &writes),
        Err(Outcome::Failed)
    );
}

#[test]
fn ordinary_observed_response_keeps_its_fee_audit_and_lane() {
    let (outcome, outputs, _) = windows(false, 0, 1024);
    assert_eq!(outcome, Outcome::Ready);
    assert_eq!(outputs.len(), 1);
    assert_eq!(
        (outputs[0].records_written, outputs[0].units_written),
        (1, 1)
    );
    assert_ne!(outputs[0].lane.len, 0);
}

#[test]
fn a_refused_delete_keeps_its_specific_error_and_caller_identity() {
    let answer = local::unrecorded_answer(
        LocalVerb::DeletePushConfig(local::Dialect::V10),
        &serde_json::json!(73),
    )
    .unwrap();
    assert_eq!(answer.status, 500);
    assert_eq!(
        serde_json::from_slice::<Value>(&answer.body).unwrap(),
        serde_json::json!({
            "jsonrpc":"2.0", "id":73, "error": {
                "code":-32603, "message":local::CONFIG_UNDELETED,
            },
        })
    );
    assert!(local::unrecorded_answer(LocalVerb::ListTasks, &Value::Null).is_none());
}
