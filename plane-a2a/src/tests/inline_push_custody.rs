// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
use super::*;

#[test]
fn fresh_inline_callback_authentication_is_durable_and_not_held_by_the_hop() {
    let mut desk = desk();
    let request = send(
        json!({"message":{"messageId":"m"}, "configuration":{"pushNotificationConfig":{"url":"https://receiver.example/cb","authentication":{"schemes":["Bearer"],"credentials":"inline-secret"}}}}),
    );
    let Opened::Hop { task, callback, .. } = opened(&mut desk, &request, ALICE) else {
        panic!("accepted callback");
    };
    assert!(
        callback.is_none(),
        "durable credential has no task-wide in-memory owner"
    );
    let cfg = local::held_config(&mut desk.book, ALICE, &task.task_id)
        .unwrap()
        .expect("durable inline config");
    assert_eq!(cfg.url, "https://receiver.example/cb");
    let deliveries = crate::push::Deliveries::default();
    let held = get(&mut desk.book, ALICE, &task.task_id, 300)
        .unwrap()
        .unwrap();
    assert!(crate::push_door::queue_moved(&deliveries, &mut desk.book, ALICE, &held.row).unwrap());
    let delivery = deliveries.next_due(0).unwrap();
    let (_, sealed) = deliveries.request(&delivery);
    assert!(sealed
        .into_iter()
        .any(|(_, name, value)| name == b"authorization"
            && crate::push::tests::sealed_bytes(value) == b"Bearer inline-secret"));
}

struct BrokenRecords;
impl Records for BrokenRecords {
    fn get(&mut self, _: &str, _: &str) -> Result<Option<Vec<u8>>, Halt> {
        Err(Halt::Failed("injected store failure".into()))
    }
    fn list(&mut self, _: &str, _: &str) -> Result<Vec<(String, Vec<u8>)>, Halt> {
        Err(Halt::Failed("injected store failure".into()))
    }
    fn claim(&mut self, _: &str, _: &str, _: u64) -> Result<bool, Halt> {
        panic!("holder must not claim")
    }
}
#[test]
fn holder_failure_is_not_a_fresh_submission() {
    for params in [
        json!({"message":{"taskId":"t1"}}),
        json!({"message":{"contextId":"ctx-1"}}),
    ] {
        assert!(matches!(
            holder(
                &mut BrokenRecords,
                &send(params),
                ALICE,
                300,
                &[MEMBER.into()]
            ),
            Err(Halt::Failed(_))
        ));
    }
}

#[test]
fn resumed_inline_config_survives_a_fresh_delivery_book_and_delete_stops_future_notifications() {
    let mut d = desk();
    let at = Stamp {
        caller: ALICE,
        request_id: "r",
        now: 150,
    };
    let mut out = Vec::new();
    tasks::tests::dispatch(&mut d.book, &at, "t1", MEMBER, &mut out).unwrap();
    d.book.apply(&out);
    for state in [TaskState::Working, TaskState::InputRequired] {
        out.clear();
        tasks::transition(&mut d.book, &at, "t1", state, &mut out).unwrap();
        d.book.apply(&out);
    }
    let request = send(
        json!({"message":{"contextId":"ctx-1"},"configuration":{"pushNotificationConfig":{"url":"https://resume.example/cb","authentication":{"schemes":["Bearer"],"credentials":"resumed-secret"}}}}),
    );
    let Opened::Hop { task, callback, .. } = opened(&mut d, &request, ALICE) else {
        panic!("resume");
    };
    assert_eq!(task.task_id, "t1");
    assert!(callback.is_none());
    assert!(local::held_config(&mut d.book, ALICE, "t1")
        .unwrap()
        .is_some());
    let row = get(&mut d.book, ALICE, "t1", 300).unwrap().unwrap().row;
    let deliveries = crate::push::Deliveries::default();
    assert!(crate::push_door::queue_moved(&deliveries, &mut d.book, ALICE, &row).unwrap());
    let deletion = Write {
        kind: KIND_PUSH_CONFIG,
        key: tasks::task_key(ALICE, "t1"),
        value: Vec::new(),
    };
    d.book.apply(std::slice::from_ref(&deletion));
    crate::push_door::forget_deleted(&deliveries, std::slice::from_ref(&deletion));
    assert!(deliveries.next_due(0).is_none());
    assert!(!crate::push_door::queue_moved(&deliveries, &mut d.book, ALICE, &row).unwrap());
}

#[test]
fn inline_token_refusal_does_not_treat_null_as_a_promised_token() {
    for token in [Value::Null, json!("unsupported"), json!(false)] {
        let mut d = desk();
        let request = send(
            json!({"message":{"messageId":"m"},"configuration":{"pushNotificationConfig":{"url":"https://receiver.example/cb","token":token}}}),
        );
        let result = opened(&mut d, &request, ALICE);
        if token.is_null() {
            assert!(matches!(result, Opened::Hop { .. }));
        } else {
            assert!(
                matches!(result, Opened::Refused(_)),
                "non-null token must be refused"
            );
        }
    }
}

#[test]
fn conflicting_task_aliases_cannot_select_an_owner_or_open_a_hop() {
    let mut d = desk();
    let request = send(json!({"id":"t1","message":{"taskId":"t2"}}));
    assert!(matches!(
        holder(&mut d, &request, ALICE, 300, &[MEMBER.into()]),
        Err(Halt::Failed(_))
    ));
    let Opened::Refused(answer) = opened(&mut d, &request, ALICE) else {
        panic!("ambiguous task aliases must be refused");
    };
    assert_eq!(answer.status, 400);
    assert_eq!(
        serde_json::from_slice::<Value>(&answer.body).unwrap()["error"]["code"],
        -32602
    );
}

#[test]
fn repeated_state_report_neither_writes_nor_trips_the_error_once_latch() {
    let mut d = desk();
    let (task, _) = hop(opened(&mut d, &send(json!({})), ALICE));
    let report = TaskSettled::Reported {
        state: TaskState::Working,
        backend_id: None,
    };
    let mut out = Vec::new();
    let latches = Latches::default();
    settle_on_answer(&mut d.book, &task, &report, ALICE, 400, &mut out, &latches).unwrap();
    d.book.apply(&out);
    out.clear();
    let before = get(&mut d.book, ALICE, &task.task_id, 400)
        .unwrap()
        .unwrap();
    let (sent, heard) = std::sync::mpsc::channel();
    let result = tracing::subscriber::with_default(Capture(sent), || {
        settle_on_answer(&mut d.book, &task, &report, ALICE, 401, &mut out, &latches)
    });
    assert!(matches!(result, Ok(None)));
    assert!(out.is_empty());
    assert!(heard.try_iter().next().is_none());
    assert_eq!(
        get(&mut d.book, ALICE, &task.task_id, 401)
            .unwrap()
            .unwrap(),
        before
    );
    let (sent, heard) = std::sync::mpsc::channel();
    tracing::subscriber::with_default(Capture(sent), || {
        settle_on_answer(&mut d.book, &task, &report, BOB, 401, &mut out, &latches).unwrap();
    });
    assert!(
        heard
            .try_iter()
            .any(|(level, _)| level == tracing::Level::WARN),
        "real failure must still own the first warning"
    );
    let (sent, heard) = std::sync::mpsc::channel();
    tracing::subscriber::with_default(Capture(sent), || {
        settle_on_answer(&mut d.book, &task, &report, BOB, 402, &mut out, &latches).unwrap();
    });
    let levels: Vec<_> = heard.try_iter().map(|(level, _)| level).collect();
    assert!(levels.contains(&tracing::Level::DEBUG));
    assert!(!levels.contains(&tracing::Level::WARN));
}

struct FailedResume(Desk);
impl Records for FailedResume {
    fn get(&mut self, k: &str, v: &str) -> Result<Option<Vec<u8>>, Halt> {
        self.0.get(k, v)
    }
    fn list(&mut self, k: &str, v: &str) -> Result<Vec<(String, Vec<u8>)>, Halt> {
        self.0.list(k, v)
    }
    fn claim(&mut self, _: &str, _: &str, _: u64) -> Result<bool, Halt> {
        panic!("task resumption must not acquire a claim")
    }
    fn observe_chain_life(&mut self, kind: &str, scope: &str) -> Result<Option<Vec<u8>>, Halt> {
        self.0.observe_chain_life(kind, scope)
    }
    fn publish(
        &mut self,
        _: &[tasks::Predicate],
        _: &[tasks::ChainLife],
        _: &[Write],
    ) -> Result<bool, Halt> {
        Err(Halt::Failed("store unavailable".into()))
    }
}
impl Reach for FailedResume {
    fn judge(&mut self, url: &str) -> Result<u64, Halt> {
        self.0.judge(url)
    }
}
impl Mint for FailedResume {
    fn random(&mut self, buf: &mut [u8]) -> Result<(), Halt> {
        self.0.random(buf)
    }
}
#[test]
fn failed_resume_is_retryable_storage_failure() {
    let mut d = desk();
    let at = Stamp {
        caller: ALICE,
        request_id: "r",
        now: 150,
    };
    let mut writes = Vec::new();
    tasks::tests::dispatch(&mut d.book, &at, "t1", MEMBER, &mut writes).unwrap();
    d.book.apply(&writes);
    for state in [TaskState::Working, TaskState::InputRequired] {
        writes.clear();
        tasks::transition(&mut d.book, &at, "t1", state, &mut writes).unwrap();
        d.book.apply(&writes);
    }
    let envelope = send(json!({"message":{"contextId":"ctx-1"}}));
    let request = Request {
        envelope: &envelope,
        relayed: None,
        relayed_bytes: None,
        caller: ALICE,
        member: MEMBER,
        addressed: None,
        now: 300,
        sweep: true,
    };
    let mut writes = Vec::new();
    let before = d.book.clone();
    let mut failed = FailedResume(d);
    let Opened::Refused(reply) =
        open(&mut failed, &request, &json!(7), &|_| None, &mut writes).unwrap()
    else {
        panic!("failed publication must refuse resume");
    };
    assert_eq!(reply.status, 503);
    assert_eq!(
        serde_json::from_slice::<Value>(&reply.body).unwrap()["error"]["code"],
        -32603
    );
    assert!(writes.is_empty());
    assert_eq!(
        failed.0.book, before,
        "failed resumption changes no task, event or config"
    );
}

#[test]
fn snake_case_inline_callback_keeps_url_and_credential_together() {
    let mut desk = desk();
    let request = send(json!({"message":{"messageId":"m"}, "configuration": {
        "task_push_notification_config": {"push_notification_config": {
            "url":"https://receiver.example/cb", "authentication": {
                "schemes":["Bearer"], "credentials":"snake-secret"
            }
        }}
    }}));
    let Opened::Hop { task, .. } = opened(&mut desk, &request, ALICE) else {
        panic!("accepted callback")
    };
    let cfg = local::held_config(&mut desk.book, ALICE, &task.task_id)
        .unwrap()
        .unwrap();
    assert_eq!(cfg.url, "https://receiver.example/cb");
    assert!(cfg.authentication.is_some());
}
