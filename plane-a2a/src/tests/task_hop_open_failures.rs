// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

/// The log lines a capture heard, with their levels.
type Lines = Vec<(tracing::Level, String)>;

/// Open `envelope` for Alice at 300 under a log capture: the opening and the captured lines.
fn open_captured(desk: &mut Desk, envelope: &Value) -> (Result<Opened, Halt>, Lines) {
    let req = Request {
        envelope,
        relayed: None,
        relayed_bytes: None,
        caller: ALICE,
        member: MEMBER,
        addressed: None,
        now: 300,
        sweep: false,
    };
    let (sent, heard) = std::sync::mpsc::channel();
    let result = tracing::subscriber::with_default(Capture(sent), || {
        open(desk, &req, &json!(7), &|_| None, &mut Vec::new())
    });
    (result, heard.try_iter().collect())
}

/// The warnings naming `stage` under the task-state diagnostic.
fn stage_warnings<'l>(lines: &'l [(tracing::Level, String)], stage: &str) -> Vec<&'l String> {
    let banner = crate::diagnostics::A2A_TASK_STATE_UNREAD
        .banner()
        .to_string();
    lines
        .iter()
        .filter(|(level, line)| {
            *level == tracing::Level::WARN && line.contains(&banner) && line.contains(stage)
        })
        .map(|(_, line)| line)
        .collect()
}

/// RED before the fix: an addressed task's inline callback the store refused made `open` fail
/// outright (`Err`), so the door answered a bare failure; it is now the plane's `503` refusal and a
/// warning that names the stage but never the store's words.
#[test]
fn an_addressed_callback_the_store_refuses_is_a_503_refusal_and_a_warning() {
    let mut desk = desk();
    desk.refuse_publication = true;
    let envelope = send(json!({
        "id": "t1",
        "configuration": { "pushNotificationConfig": { "url": "https://hook.example/t1" } },
    }));
    let (result, lines) = open_captured(&mut desk, &envelope);
    let opened = result.expect("a refusal, not a failed opening");
    let (status, code, message) = refusal_of(opened);
    assert_eq!((status, code), (503, -32603));
    assert_eq!(message, CALLBACK_UNRECORDED);
    assert!(
        !stage_warnings(&lines, "callback").is_empty(),
        "the operator is told: {lines:?}"
    );
    assert!(
        lines
            .iter()
            .all(|(_, line)| !line.contains("store refused publication")),
        "the store's words are not journaled: {lines:?}"
    );
}

/// RED before the fix: a fresh task the store refused answered `503` with nothing in the plane's
/// log; the refusal now carries a warning naming the stage.
#[test]
fn a_fresh_task_the_store_refuses_is_warned_without_the_stores_words() {
    let mut desk = desk();
    desk.refuse_publication = true;
    let (result, lines) = open_captured(&mut desk, &send(json!({})));
    let (status, _, message) = refusal_of(result.unwrap());
    assert_eq!((status, message.as_str()), (503, TASK_UNRECORDED));
    assert!(
        !stage_warnings(&lines, "task_open").is_empty(),
        "the operator is told: {lines:?}"
    );
    assert!(lines
        .iter()
        .all(|(_, line)| !line.contains("store refused publication")));
}

/// RED before the fix: a resume the store refused answered `503` with nothing in the plane's log.
#[test]
fn a_resume_the_store_refuses_is_warned_without_the_stores_words() {
    let mut desk = desk();
    let mut out = Vec::new();
    let at = Stamp {
        caller: ALICE,
        request_id: "r",
        now: 150,
    };
    tasks::tests::dispatch(&mut desk.book, &at, "t1", MEMBER, &mut out).unwrap();
    for to in [TaskState::Working, TaskState::InputRequired] {
        tasks::transition(&mut desk.book, &at, "t1", to, &mut out).unwrap();
    }
    desk.refuse_publication = true;
    let (result, lines) = open_captured(
        &mut desk,
        &send(json!({ "message": { "contextId": "ctx-1" } })),
    );
    let (status, _, message) = refusal_of(result.unwrap());
    assert_eq!((status, message.as_str()), (503, TASK_UNRESUMED));
    assert!(
        !stage_warnings(&lines, "task_resume").is_empty(),
        "the operator is told: {lines:?}"
    );
    assert!(lines
        .iter()
        .all(|(_, line)| !line.contains("store refused publication")));
}

/// The host records of a [`Desk`], counting the task rows read.
struct Counting<'d> {
    desk: &'d mut Desk,
    task_reads: usize,
}

impl Records for Counting<'_> {
    fn get(&mut self, kind: &str, key: &str) -> Result<Option<Vec<u8>>, Halt> {
        if kind == KIND_TASK {
            self.task_reads += 1;
        }
        self.desk.get(kind, key)
    }
    fn list(&mut self, kind: &str, prefix: &str) -> Result<Vec<(String, Vec<u8>)>, Halt> {
        self.desk.list(kind, prefix)
    }
    fn observe_chain_life(&mut self, kind: &str, scope: &str) -> Result<Option<Vec<u8>>, Halt> {
        self.desk.observe_chain_life(kind, scope)
    }
    fn publish(
        &mut self,
        predicates: &[tasks::Predicate],
        chains: &[tasks::ChainLife],
        writes: &[Write],
    ) -> Result<bool, Halt> {
        self.desk.publish(predicates, chains, writes)
    }
}

impl Reach for Counting<'_> {
    fn judge(&mut self, dest: &str) -> Result<u64, Halt> {
        self.desk.judge(dest)
    }
}

impl Mint for Counting<'_> {
    fn random(&mut self, buf: &mut [u8]) -> Result<(), Halt> {
        self.desk.random(buf)
    }
}

/// RED before the fix: the addressed task's row was read twice (once to admit it, once again to
/// translate its id); it is read once and still sent on as the far end's id.
#[test]
fn an_addressed_task_is_read_once_and_still_translated() {
    let mut desk = desk();
    let mut counting = Counting {
        desk: &mut desk,
        task_reads: 0,
    };
    let cancel =
        json!({ "jsonrpc": "2.0", "id": 7, "method": "CancelTask", "params": { "id": "t1" } });
    let req = Request {
        envelope: &cancel,
        relayed: None,
        relayed_bytes: None,
        caller: ALICE,
        member: MEMBER,
        addressed: None,
        now: 300,
        sweep: false,
    };
    let back = |id: &str| (id == "t1").then(|| "far-t1".to_string());
    let opened = open(&mut counting, &req, &json!(7), &back, &mut Vec::new()).unwrap();
    assert_eq!(counting.task_reads, 1, "the held row is read once");
    let (_, instead) = hop(opened);
    let sent: Value = serde_json::from_slice(&instead.expect("translated")).unwrap();
    assert_eq!(sent["params"]["id"], "far-t1");
}
