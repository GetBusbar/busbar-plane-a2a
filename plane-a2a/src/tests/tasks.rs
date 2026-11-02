// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The task store over host records, against [`Book`]: a map that answers `records.get/list/claim`

use std::collections::{BTreeMap, BTreeSet};

use super::*;

#[path = "task_open_dispatch.rs"]
mod task_open_dispatch;

#[path = "task_sweep_gate.rs"]
mod task_sweep_gate;

#[path = "task_conditional_publication.rs"]
mod task_conditional_publication;

/// SUBMIT `row` for the caller: the task, and its chain's genesis event, stamped with the row's
pub(crate) fn submit(
    rec: &mut dyn Records,
    at: &Stamp<'_>,
    mut row: TaskRow,
    out: &mut Vec<Write>,
) -> Result<TaskRow, Halt> {
    if !is_caller(at.caller) {
        return Err(Halt::Failed("no caller to hold the task under".into()));
    }
    row.principal = at.caller.to_string();
    let genesis = HeldTask {
        row: row.clone(),
        next_seq: 1,
    };
    let at = Stamp {
        now: row.created_at,
        ..*at
    };
    submit_held(rec, &at, &genesis, row, out).map(|held| held.row)
}

/// DISPATCH: record the agent the task went to, with a `task.delegated` event.
pub(crate) fn dispatch(
    rec: &mut dyn Records,
    at: &Stamp<'_>,
    task: &str,
    agent_id: &str,
    out: &mut Vec<Write>,
) -> Result<Option<TaskRow>, Halt> {
    let mut plan = |row: &TaskRow| -> Planned {
        let mut next = row.clone();
        next.agent_id = agent_id.to_string();
        next.updated_at = at.now;
        Ok(Some((next, EV_DELEGATED)))
    };
    change(rec, at, task, &mut plan, out)
}

/// ADVANCE the artifact cursor to `cursor`, monotonic, with a `task.artifact` event; nothing when it
pub(crate) fn advance_cursor(
    rec: &mut dyn Records,
    at: &Stamp<'_>,
    task: &str,
    cursor: u64,
    out: &mut Vec<Write>,
) -> Result<Option<TaskRow>, Halt> {
    let mut plan = |row: &TaskRow| -> Planned {
        if cursor <= row.artifact_cursor {
            return Ok(None);
        }
        let mut next = row.clone();
        next.artifact_cursor = cursor;
        next.updated_at = at.now;
        Ok(Some((next, EV_ARTIFACT)))
    };
    change(rec, at, task, &mut plan, out)
}

/// THE HOST RECORDS, as a test holds them.
#[derive(Debug, Default, Clone, PartialEq)]
pub(crate) struct Book {
    rows: BTreeMap<(String, String), Vec<u8>>,
    claims: BTreeSet<(String, String)>,
    /// Another writer's change, applied the moment this one next claims, so this one loses.
    race: Option<Vec<Write>>,
    /// Complete atomic publications acknowledged by this host.
    pub(crate) publications: Vec<Vec<Write>>,
    lives: BTreeMap<(String, String), Vec<u8>>,
}

/// One length-prefixed field: its length as eight big-endian bytes, then the bytes.
fn framed(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// The host's digest of event `e` on the chain `scope`: the length-prefixed prelude
pub(crate) fn host_digest(scope: &str, e: &TaskEventRow) -> String {
    let mut input = Vec::new();
    framed(&mut input, e.prev_hash.as_bytes());
    framed(&mut input, scope.as_bytes());
    framed(&mut input, &e.seq.to_be_bytes());
    input.extend_from_slice(&suffix(e));
    busbar_contract::redacted::sha256_hex(&input)
}

/// The fields of the door's own length-prefixed bytes, in order.
fn unframed(mut own: &[u8]) -> Vec<Vec<u8>> {
    let mut fields = Vec::new();
    while !own.is_empty() {
        let (len, rest) = own.split_at(8);
        let len = u64::from_be_bytes(len.try_into().unwrap()) as usize;
        fields.push(rest[..len].to_vec());
        own = &rest[len..];
    }
    fields
}

/// The chain a held event key belongs to and its sequence.
fn chain_of(key: &str) -> Option<(String, u64)> {
    busbar_contract::services::chain_key_parts(key.as_bytes())
        .map(|(scope, seq)| (String::from_utf8_lossy(scope).into_owned(), seq))
}

impl Book {
    /// Apply an answer's writes: a put, or an empty value's tombstone; on the chained kind, an
    pub(crate) fn apply(&mut self, writes: &[Write]) {
        for w in writes {
            if w.kind == KIND_TASK_EVENT {
                self.chain(&w.key, &w.value);
                continue;
            }
            let at = (w.kind.to_string(), w.key.clone());
            if w.value.is_empty() {
                self.rows.remove(&at);
            } else {
                self.rows.insert(at, w.value.clone());
            }
        }
    }

    /// THE HOST'S APPEND to the chain `scope` (`<caller>/<task>`): the next sequence, the tail's
    fn chain(&mut self, scope: &str, own: &[u8]) {
        let held: Vec<(String, String)> = self
            .rows
            .keys()
            .filter(|(k, key)| {
                k == KIND_TASK_EVENT && chain_of(key).is_some_and(|(s, _)| s == scope)
            })
            .cloned()
            .collect();
        if own.is_empty() {
            for at in held {
                self.rows.remove(&at);
            }
            return;
        }
        let last = held.last().map(|at| self.event_at(at));
        let fields = unframed(own);
        assert_eq!(
            fields.len(),
            6,
            "the door's own bytes: ts, kind, context, principal, agent, state"
        );
        let text = |i: usize| String::from_utf8(fields[i].clone()).unwrap();
        let mut ev = TaskEventRow {
            task_id: scope.split_once('/').unwrap().1.to_string(),
            seq: last.as_ref().map_or(1, |e| e.seq + 1),
            ts: u64::from_be_bytes(fields[0].as_slice().try_into().unwrap()),
            kind: text(1),
            context_id: text(2),
            principal: text(3),
            agent_id: text(4),
            state: text(5),
            request_id: String::new(),
            prev_hash: last.map(|e| e.hash).unwrap_or_default(),
            hash: String::new(),
            digest_version: DIGEST_VERSION_LEN_PREFIXED,
        };
        assert_eq!(suffix(&ev), own, "the door's bytes read back whole");
        ev.hash = host_digest(scope, &ev);
        let key = String::from_utf8(busbar_contract::services::chain_key(
            scope.as_bytes(),
            ev.seq,
        ))
        .unwrap();
        self.rows.insert(
            (KIND_TASK_EVENT.to_string(), key),
            serde_json::to_vec(&ev).unwrap(),
        );
    }

    fn event_at(&self, at: &(String, String)) -> TaskEventRow {
        serde_json::from_slice(&self.rows[at]).unwrap()
    }

    /// THE HOST'S VERIFIED READ of the chains under `prefix`: each chain's records, and ahead of
    fn chains(&self, prefix: &str) -> Vec<(String, Vec<u8>)> {
        let mut by_chain: BTreeMap<String, Vec<(String, TaskEventRow)>> = BTreeMap::new();
        for at in self.rows.keys() {
            if at.0 != KIND_TASK_EVENT || !at.1.starts_with(prefix) {
                continue;
            }
            if let Some((scope, _)) = chain_of(&at.1) {
                by_chain
                    .entry(scope)
                    .or_default()
                    .push((at.1.clone(), self.event_at(at)));
            }
        }
        let mut out = BTreeMap::new();
        for (scope, events) in by_chain {
            let mut prev = String::new();
            let mut broke = None;
            for (i, (_, e)) in events.iter().enumerate() {
                let fine = e.seq == i as u64 + 1
                    && e.prev_hash == prev
                    && host_digest(&scope, e) == e.hash;
                if !fine && broke.is_none() {
                    broke = Some(e.seq);
                }
                prev = e.hash.clone();
            }
            if let Some(seq) = broke {
                out.insert(
                    scope.clone(),
                    format!("the chain for scope `{scope}` BROKEN at seq {seq}").into_bytes(),
                );
            }
            for (key, _) in events {
                let at = (KIND_TASK_EVENT.to_string(), key.clone());
                out.insert(key, self.rows[&at].clone());
            }
        }
        out.into_iter().collect()
    }

    /// Rewrite `caller`'s task `task`'s event `seq` behind the host's back, its digest left alone.
    pub(crate) fn tamper(
        &mut self,
        caller: &str,
        task: &str,
        seq: u64,
        edit: impl FnOnce(&mut TaskEventRow),
    ) {
        let at = (KIND_TASK_EVENT.to_string(), event_key(caller, task, seq));
        let mut e = self.event_at(&at);
        edit(&mut e);
        self.rows.insert(at, serde_json::to_vec(&e).unwrap());
    }

    /// The live value of `kind` under `key`.
    pub(crate) fn value(&self, kind: &str, key: &str) -> Option<&Vec<u8>> {
        self.rows.get(&(kind.to_string(), key.to_string()))
    }

    /// Put `held` as `caller`'s task, as a write would.
    pub(crate) fn hold(&mut self, caller: &str, held: &HeldTask) {
        self.apply(&[Write {
            kind: KIND_TASK,
            key: task_key(caller, &held.row.task_id),
            value: serde_json::to_vec(held).unwrap(),
        }]);
    }
}

impl Records for Book {
    fn get(&mut self, kind: &str, key: &str) -> Result<Option<Vec<u8>>, Halt> {
        Ok(self.value(kind, key).cloned())
    }

    fn list(&mut self, kind: &str, prefix: &str) -> Result<Vec<(String, Vec<u8>)>, Halt> {
        if kind == KIND_TASK_EVENT {
            return Ok(self.chains(prefix));
        }
        Ok(self
            .rows
            .iter()
            .filter(|((k, key), _)| k == kind && key.starts_with(prefix))
            .map(|((_, key), v)| (key.clone(), v.clone()))
            .collect())
    }

    fn claim(&mut self, kind: &str, key: &str, _ttl_ms: u64) -> Result<bool, Halt> {
        if let Some(theirs) = self.race.take() {
            self.apply(&theirs);
            self.claims.insert((kind.to_string(), key.to_string()));
        }
        Ok(self.claims.insert((kind.to_string(), key.to_string())))
    }

    fn observe_chain_life(&mut self, kind: &str, scope: &str) -> Result<Option<Vec<u8>>, Halt> {
        Ok(self
            .lives
            .get(&(kind.to_string(), scope.to_string()))
            .cloned())
    }

    fn publish(
        &mut self,
        predicates: &[Predicate],
        chains: &[ChainLife],
        writes: &[Write],
    ) -> Result<bool, Halt> {
        if let Some(theirs) = self.race.take() {
            self.apply(&theirs);
        }
        if predicates
            .iter()
            .any(|p| self.value(p.kind, &p.key) != p.expected.as_ref())
            || chains.iter().any(|c| {
                self.lives.get(&(c.kind.to_string(), c.scope.clone())) != c.expected.as_ref()
            })
        {
            return Ok(false);
        }
        self.apply(writes);
        for write in writes
            .iter()
            .filter(|w| w.kind == KIND_TASK_EVENT && w.value.is_empty())
        {
            let key = (write.kind.to_string(), write.key.clone());
            let life = self
                .lives
                .get(&key)
                .map(|bytes| u64::from_be_bytes(bytes.as_slice().try_into().unwrap()))
                .unwrap_or(0);
            self.lives
                .insert(key, life.checked_add(1).unwrap().to_be_bytes().to_vec());
        }
        self.publications.push(writes.to_vec());
        Ok(true)
    }
}

/// Two callers' references.
pub(crate) const ALICE: &str = "a11ce";
pub(crate) const BOB: &str = "b0b";

/// A row for `task`, submitted at `now`.
pub(crate) fn row(task: &str, now: u64) -> TaskRow {
    crate::a2a::task::Task::submitted(
        task,
        "ctx-1",
        "someone",
        crate::a2a::task::Direction::Inbound,
        now,
    )
    .unwrap()
    .to_row()
}

/// `caller`'s step at `now`.
pub(crate) fn step(caller: &str, now: u64) -> Stamp<'_> {
    Stamp {
        caller,
        request_id: "req-1",
        now,
    }
}

/// Submit `task` for `caller` at `now` and apply it.
pub(crate) fn submitted(book: &mut Book, caller: &str, task: &str, now: u64) {
    let mut out = Vec::new();
    submit(book, &step(caller, now), row(task, now), &mut out).unwrap();
    book.apply(&out);
}

fn event(book: &Book, caller: &str, task: &str, seq: u64) -> TaskEventRow {
    serde_json::from_slice(
        book.value(KIND_TASK_EVENT, &event_key(caller, task, seq))
            .unwrap(),
    )
    .unwrap()
}

/// A real inbound task leaves a chain that RECOMPUTES from the persisted rows: opening a relayed
#[test]
fn an_inbound_task_leaves_a_verifying_chain_in_the_store_the_front_door_wrote_it_to() {
    let mut book = Book::default();
    let mut out = Vec::new();
    open(
        &mut book,
        &step(ALICE, 100),
        row("t1", 100),
        "planner",
        &mut out,
    )
    .unwrap();
    book.apply(&out);

    let events: Vec<TaskEventRow> = (1..=2).map(|seq| event(&book, ALICE, "t1", seq)).collect();
    assert!(
        book.value(KIND_TASK_EVENT, &event_key(ALICE, "t1", 3))
            .is_none(),
        "submitted and delegated, nothing more"
    );
    let kinds: Vec<&str> = events.iter().map(|e| e.kind.as_str()).collect();
    assert_eq!(kinds, [EV_SUBMITTED, EV_DELEGATED]);
    assert_eq!(
        events[0].seq, 1,
        "the chain the front door opened starts at seq 1"
    );
    assert!(
        events[0].prev_hash.is_empty(),
        "a genesis event has no predecessor to link to"
    );
    assert_eq!(
        events[1].agent_id, "planner",
        "who was delegated to is on the chain"
    );
    let mut previous = String::new();
    for e in &events {
        assert_eq!(
            e.prev_hash, previous,
            "seq {} links to its predecessor",
            e.seq
        );
        assert_eq!(
            host_digest(&task_key(ALICE, "t1"), e),
            e.hash,
            "seq {} recomputes from its own fields",
            e.seq
        );
        assert_eq!(e.task_id, "t1");
        assert_eq!(e.principal, ALICE);
        previous = e.hash.clone();
    }
    let held = get(&mut book, ALICE, "t1", 100).unwrap().unwrap();
    assert_eq!(held.next_seq, 3, "the held row claims the next sequence");
    assert!(
        book.list(KIND_TASK_EVENT, "").unwrap().len() == 2,
        "the host reads the chain back verified: no break announced"
    );
    assert!(!previous.is_empty());
}

/// A task is held under its caller's prefix: its caller reads it back, another caller reads the same
#[test]
fn a_task_is_read_back_by_its_caller_only() {
    let mut book = Book::default();
    submitted(&mut book, ALICE, "t1", 100);
    submitted(&mut book, BOB, "t2", 100);
    let held = get(&mut book, ALICE, "t1", 100).unwrap().unwrap();
    assert_eq!(held.row.principal, ALICE, "the row is the caller's");
    assert_eq!((held.next_seq, held.row.state.as_str()), (2, "submitted"));
    assert_eq!(get(&mut book, BOB, "t1", 100).unwrap(), None);
    assert_eq!(get(&mut book, ALICE, "nope", 100).unwrap(), None);
    let ids: Vec<String> = list(&mut book, ALICE, 100)
        .unwrap()
        .into_iter()
        .map(|r| r.task_id)
        .collect();
    assert_eq!(ids, vec!["t1".to_string()]);
    for nobody in ["", "A11CE", "a/b"] {
        assert_eq!(
            get(&mut book, nobody, "t1", 100).unwrap(),
            None,
            "{nobody:?} holds nothing"
        );
        assert!(submit(&mut book, &step(nobody, 1), row("t9", 1), &mut Vec::new()).is_err());
    }
}

/// A change chains its event onto the tail the task record carries, under the digest, and a second
#[test]
fn a_change_chains_its_event_onto_the_tail() {
    let mut book = Book::default();
    submitted(&mut book, ALICE, "t1", 100);
    let mut out = Vec::new();
    let moved = transition(
        &mut book,
        &step(ALICE, 160),
        "t1",
        TaskState::Working,
        &mut out,
    )
    .unwrap();
    book.apply(&out);
    assert_eq!(moved.map(|r| r.state), Some("working".to_string()));
    let (e1, e2) = (event(&book, ALICE, "t1", 1), event(&book, ALICE, "t1", 2));
    assert_eq!(
        (e1.kind.as_str(), e1.prev_hash.as_str(), e1.ts),
        (EV_SUBMITTED, "", 100)
    );
    assert_eq!((e2.kind.as_str(), e2.ts), ("task.working", 160));
    assert_eq!(e2.prev_hash, e1.hash);
    for e in [&e1, &e2] {
        assert_eq!(host_digest(&task_key(ALICE, "t1"), e), e.hash);
    }
    let held = get(&mut book, ALICE, "t1", 160).unwrap().unwrap();
    assert_eq!(held.next_seq, 3);
    let again = submit(
        &mut book,
        &step(ALICE, 200),
        row("t1", 200),
        &mut Vec::new(),
    );
    assert!(
        matches!(again, Err(Halt::Failed(_))),
        "the genesis sequence is taken"
    );
    let illegal = transition(
        &mut book,
        &step(ALICE, 170),
        "t1",
        TaskState::Submitted,
        &mut Vec::new(),
    );
    assert!(matches!(illegal, Err(Halt::Failed(_))));
}

/// RACE-SAFE: a writer that loses its sequence to another writer re-reads and takes the next one,
#[test]
fn a_change_that_loses_its_sequence_takes_the_next() {
    let mut book = Book::default();
    submitted(&mut book, ALICE, "t1", 100);
    let mut rival = book.clone();
    dispatch(
        &mut rival,
        &step(ALICE, 110),
        "t1",
        "planner",
        &mut Vec::new(),
    )
    .unwrap();
    book.race = rival.publications.pop();
    let mut out = Vec::new();
    transition(
        &mut book,
        &step(ALICE, 120),
        "t1",
        TaskState::Working,
        &mut out,
    )
    .unwrap();
    book.apply(&out);
    let held = get(&mut book, ALICE, "t1", 120).unwrap().unwrap();
    assert_eq!(
        held.row.agent_id, "planner",
        "the other writer's change stands"
    );
    assert_eq!(held.row.state, "working");
    assert_eq!(held.next_seq, 4);
    let (e2, e3) = (event(&book, ALICE, "t1", 2), event(&book, ALICE, "t1", 3));
    assert_eq!(
        (e2.kind.as_str(), e3.kind.as_str()),
        ("task.delegated", "task.working")
    );
    assert_eq!(e3.prev_hash, e2.hash);
}

/// The cursor only moves forward; a push delivery chains an event and leaves the row alone.
#[test]
fn the_cursor_moves_forward_and_a_delivery_only_chains() {
    let mut book = Book::default();
    submitted(&mut book, ALICE, "t1", 100);
    let mut out = Vec::new();
    assert!(
        advance_cursor(&mut book, &step(ALICE, 110), "t1", 3, &mut out)
            .unwrap()
            .is_some()
    );
    book.apply(&out);
    assert_eq!(
        advance_cursor(&mut book, &step(ALICE, 120), "t1", 2, &mut Vec::new()).unwrap(),
        None
    );
    let mut out = Vec::new();
    record_push_delivery(
        &mut book,
        &step(ALICE, 130),
        "t1",
        "task.push_delivered",
        &mut out,
    )
    .unwrap();
    book.apply(&out);
    let held = get(&mut book, ALICE, "t1", 130).unwrap().unwrap();
    assert_eq!((held.row.artifact_cursor, held.row.updated_at), (3, 110));
    assert_eq!(event(&book, ALICE, "t1", 3).ts, 130);
}

/// A terminal task past its window reads as absent: the engine's `evict_terminal` window.
#[test]
fn a_terminal_task_past_its_window_reads_as_absent() {
    let mut book = Book::default();
    submitted(&mut book, ALICE, "t1", 100);
    let mut out = Vec::new();
    transition(
        &mut book,
        &step(ALICE, 200),
        "t1",
        TaskState::Completed,
        &mut out,
    )
    .unwrap();
    book.apply(&out);
    assert!(get(&mut book, ALICE, "t1", 200 + TERMINAL_TTL_SECS)
        .unwrap()
        .is_some());
    assert!(get(&mut book, ALICE, "t1", 201 + TERMINAL_TTL_SECS)
        .unwrap()
        .is_none());
    assert!(list(&mut book, ALICE, 201 + TERMINAL_TTL_SECS)
        .unwrap()
        .is_empty());
}

/// THE SWEEP: an expired terminal task goes as tombstones (its row, its events, its push config),
#[test]
fn the_sweep_tombstones_the_expired_and_leaves_the_idle_active() {
    let mut book = Book::default();
    submitted(&mut book, ALICE, "t1", 100);
    submitted(&mut book, ALICE, "t10", 100);
    submitted(&mut book, BOB, "idle", 100);
    let mut out = Vec::new();
    transition(
        &mut book,
        &step(ALICE, 100),
        "t1",
        TaskState::Completed,
        &mut out,
    )
    .unwrap();
    book.apply(&out);
    book.apply(&[Write {
        kind: KIND_PUSH_CONFIG,
        key: task_key(ALICE, "t1"),
        value: b"{}".to_vec(),
    }]);
    let now = 101 + 86_400;
    let mut out = Vec::new();
    retention_sweep(&mut book, now, 64, &mut out).unwrap();
    book.apply(&out);
    assert!(book.value(KIND_TASK, &task_key(ALICE, "t1")).is_none());
    assert!(book
        .value(KIND_PUSH_CONFIG, &task_key(ALICE, "t1"))
        .is_none());
    assert!(book
        .value(KIND_TASK_EVENT, &event_key(ALICE, "t1", 1))
        .is_none());
    assert!(
        book.value(KIND_TASK_EVENT, &event_key(ALICE, "t10", 1))
            .is_some(),
        "not its events"
    );
    for (caller, task) in [(ALICE, "t10"), (BOB, "idle")] {
        let held = get(&mut book, caller, task, now).unwrap().unwrap();
        assert_eq!(held.row.state, "submitted", "{task} is active and stays so");
        assert!(
            book.value(KIND_TASK_EVENT, &event_key(caller, task, 2))
                .is_none(),
            "{task} gained no event"
        );
    }
}

/// Retention sweeping preserves active tasks and their push tokens.
#[test]
fn an_idle_active_task_survives_the_sweep_with_its_push_token() {
    let mut book = Book::default();
    submitted(&mut book, ALICE, "idle", 100);
    let tokens = crate::push::Tokens::default();
    let token = tokens.mint(ALICE, "idle", b"sig").unwrap();
    let now = 100 + 86_400 * 30;
    let mut out = Vec::new();
    retention_sweep(&mut book, now, 64, &mut out).unwrap();
    book.apply(&out);
    let held = get(&mut book, ALICE, "idle", now).unwrap().unwrap();
    assert_eq!(
        held.row.state, "submitted",
        "an idle active task is not canceled"
    );
    assert_eq!(held.row.updated_at, 100, "the sweep wrote nothing to it");
    assert_eq!(
        list(&mut book, ALICE, now).unwrap().len(),
        1,
        "ListTasks still has it"
    );
    assert!(
        tokens.claim(&token).is_some(),
        "its push token stays valid while the task is active"
    );
}

/// THE CAP: while MAX_RETAINED or more TERMINAL tasks are held, the oldest go; active tasks are
#[test]
fn the_sweep_holds_the_cap_with_terminal_tasks_only() {
    let mut book = Book::default();
    let held = |task: String, state: &str, at: u64| {
        let mut row = row(&task, at);
        row.state = state.to_string();
        HeldTask { row, next_seq: 2 }
    };
    for i in 0..5 {
        book.hold(ALICE, &held(format!("act{i}"), "working", 5));
    }
    for i in 0..MAX_RETAINED - 1 {
        book.hold(ALICE, &held(format!("a{i:05}"), "completed", 50));
    }
    book.hold(ALICE, &held("old".into(), "completed", 10));
    book.hold(ALICE, &held("new".into(), "completed", 20));
    let mut out = Vec::new();
    retention_sweep(&mut book, 30, 1, &mut out).unwrap();
    book.apply(&out);
    assert!(
        book.value(KIND_TASK, &task_key(ALICE, "old")).is_none(),
        "the oldest terminal first"
    );
    assert!(
        book.value(KIND_TASK, &task_key(ALICE, "new")).is_some(),
        "the budget was one"
    );
    let mut out = Vec::new();
    retention_sweep(&mut book, 30, 64, &mut out).unwrap();
    book.apply(&out);
    assert!(book.value(KIND_TASK, &task_key(ALICE, "new")).is_none());
    assert_eq!(
        list(&mut book, ALICE, 30).unwrap().len(),
        MAX_RETAINED - 1 + 5,
        "the cap held over terminal tasks; no active task goes"
    );
}

/// Apply `to` for ALICE's `task` at `now` through [`transition`] and the book.
fn moved_to(book: &mut Book, task: &str, to: TaskState, now: u64) {
    let mut out = Vec::new();
    transition(book, &step(ALICE, now), task, to, &mut out).unwrap();
    book.apply(&out);
}

/// Ported from busbar-a2a a2a/tests/taskstore_tests.rs::an_interrupt_resumes_after_a_restart_and_its_chain_continues.
#[test]
fn an_interrupt_resumes_after_a_restart_and_its_chain_continues() {
    let mut book = Book::default();
    submitted(&mut book, ALICE, "t-paused", 100);
    moved_to(&mut book, "t-paused", TaskState::Working, 110);
    moved_to(&mut book, "t-paused", TaskState::AuthRequired, 120);
    let before = get(&mut book, ALICE, "t-paused", 130).unwrap().unwrap();
    assert_eq!(before.row.state, "auth-required");
    assert_eq!(before.next_seq, 4, "process 1 wrote a real chain");

    let mut after_restart = book.clone();
    moved_to(&mut after_restart, "t-paused", TaskState::Working, 200);

    let held = get(&mut after_restart, ALICE, "t-paused", 200)
        .unwrap()
        .unwrap();
    assert_eq!(held.row.state, "working");
    assert_eq!(held.next_seq, 5, "exactly one event was appended");
    let last = event(&after_restart, ALICE, "t-paused", 4);
    assert_eq!(last.seq, 4, "the sequence CONTINUED");
    assert_eq!(
        last.kind, "task.resumed",
        "resuming from an interrupt is its own event kind, not a plain `working`"
    );
    assert_eq!(
        last.prev_hash,
        event(&after_restart, ALICE, "t-paused", 3).hash,
        "the chain links across the restart boundary"
    );
    assert_eq!(host_digest(&task_key(ALICE, "t-paused"), &last), last.hash);
}

/// Ported from busbar-a2a a2a/tests/taskstore_tests.rs::the_task_event_digest_covers_every_content_field_and_excludes_the_join_key.
#[test]
fn the_task_event_digest_covers_every_content_field_and_excludes_the_join_key() {
    let base = TaskEventRow {
        task_id: "task-1".into(),
        seq: 2,
        ts: 1_700_000_060,
        kind: "task.working".into(),
        context_id: "ctx-1".into(),
        principal: "vk_alice".into(),
        agent_id: "planner".into(),
        state: "working".into(),
        request_id: "req-2".into(),
        prev_hash: "07d3b2028b0729c42fdaae5f4d59c3a98749aa88db89caabcacb5ebe3981ec28".into(),
        hash: String::new(),
        digest_version: DIGEST_VERSION_LEN_PREFIXED,
    };

    {
        let TaskEventRow {
            task_id: _,
            seq: _,
            ts: _,
            kind: _,
            context_id: _,
            principal: _,
            agent_id: _,
            state: _,
            request_id: _,
            prev_hash: _,
            hash: _,
            digest_version: _,
        } = &base;
    }
    let reference = suffix(&base);
    let mut chained = BTreeSet::new();
    let mut ignored = BTreeSet::new();
    let mut mutate = |name: &'static str, edit: fn(&mut TaskEventRow)| {
        let mut e = base.clone();
        edit(&mut e);
        if suffix(&e) == reference {
            ignored.insert(name);
        } else {
            chained.insert(name);
        }
    };
    mutate("ts", |e| e.ts += 1);
    mutate("kind", |e| e.kind.push('x'));
    mutate("context_id", |e| e.context_id.push('x'));
    mutate("principal", |e| e.principal.push('x'));
    mutate("agent_id", |e| e.agent_id.push('x'));
    mutate("state", |e| e.state.push('x'));
    mutate("request_id", |e| e.request_id = "req-other".to_string());
    assert_eq!(
        chained,
        ["ts", "kind", "context_id", "principal", "agent_id", "state"]
            .into_iter()
            .collect::<BTreeSet<&str>>(),
        "exactly these content fields are inside the digest"
    );
    assert_eq!(
        ignored,
        ["request_id"].into_iter().collect::<BTreeSet<&str>>(),
        "request_id is the ONLY content field outside the digest: a join key absent on paths with \
         no inbound request must not make an intact chain unverifiable"
    );
}

/// Ported from busbar-a2a a2a/tests/taskstore_tests.rs::a_mutation_against_an_unknown_task_is_refused.
#[test]
fn a_mutation_against_an_unknown_task_is_refused() {
    let mut book = Book::default();
    let at = step(ALICE, 100);
    let mut out = Vec::new();
    for refused in [
        transition(&mut book, &at, "nope", TaskState::Working, &mut out).map(|_| ()),
        dispatch(&mut book, &at, "nope", "a", &mut out).map(|_| ()),
        advance_cursor(&mut book, &at, "nope", 1, &mut out).map(|_| ()),
    ] {
        match refused {
            Err(Halt::Failed(why)) => assert!(why.contains("no such task"), "{why}"),
            other => panic!("an unknown task id must be refused, got {other:?}"),
        }
    }
    assert!(out.is_empty(), "nothing was written: {out:?}");
    assert_eq!(book.rows.len(), 0, "and nothing was created");
}

/// Ported from busbar-a2a a2a/tests/taskstore_tests.rs::an_illegal_transition_writes_neither_a_row_nor_an_event.
#[test]
fn an_illegal_transition_writes_neither_a_row_nor_an_event() {
    let mut book = Book::default();
    submitted(&mut book, ALICE, "t-work", 100);
    moved_to(&mut book, "t-work", TaskState::Working, 110);
    moved_to(&mut book, "t-work", TaskState::Completed, 120);
    let rows_before = book.rows.clone();

    let mut out = Vec::new();
    let err = transition(
        &mut book,
        &step(ALICE, 130),
        "t-work",
        TaskState::Working,
        &mut out,
    )
    .expect_err("terminal is terminal");
    match err {
        Halt::Failed(why) => assert!(why.contains("illegal task transition"), "{why}"),
        other => panic!("expected a refusal in the state machine's words, got {other:?}"),
    }
    assert!(out.is_empty(), "a refused move wrote {out:?}");
    assert_eq!(book.rows, rows_before, "the store is untouched");
}

/// "Process 1" (the engine's `process_one`): ALICE's `t-work` taken to `working`; BOB's
fn process_one() -> Book {
    let mut book = Book::default();
    submitted(&mut book, ALICE, "t-work", 100);
    moved_to(&mut book, "t-work", TaskState::Working, 101);
    submitted(&mut book, BOB, "t-paused", 100);
    type Change = fn(&mut Book, &mut Vec<Write>) -> Result<(), Halt>;
    let changes: [Change; 4] = [
        |b: &mut Book, out: &mut Vec<Write>| {
            dispatch(b, &step(BOB, 101), "t-paused", "planner", out).map(|_| ())
        },
        |b: &mut Book, out: &mut Vec<Write>| {
            transition(b, &step(BOB, 102), "t-paused", TaskState::Working, out).map(|_| ())
        },
        |b: &mut Book, out: &mut Vec<Write>| {
            advance_cursor(b, &step(BOB, 103), "t-paused", 7, out).map(|_| ())
        },
        |b: &mut Book, out: &mut Vec<Write>| {
            transition(b, &step(BOB, 104), "t-paused", TaskState::AuthRequired, out).map(|_| ())
        },
    ];
    for change in changes {
        let mut out = Vec::new();
        change(&mut book, &mut out).unwrap();
        book.apply(&out);
    }
    book
}

/// Ported from busbar-a2a a2a/tests/taskstore_tests.rs::the_ram_default_loses_every_in_flight_task_and_the_registry_says_so.
#[test]
fn the_ram_default_loses_every_in_flight_task_and_the_registry_says_so() {
    let mut process_1 = process_one();
    assert_eq!(
        restore(&mut process_1).unwrap().active,
        2,
        "process 1 holds both tasks in its records"
    );

    let mut process_2 = Book::default();
    assert_eq!(
        restore(&mut process_2).unwrap(),
        Restored::default(),
        "the memory store restores NOTHING: durability is a property of the configured backend"
    );
    assert!(
        get(&mut process_2, BOB, "t-paused", 105).unwrap().is_none(),
        "the interrupted task is genuinely gone"
    );
}

/// Ported from busbar-a2a a2a/tests/taskstore_tests.rs::a_tampered_chain_is_reported_on_restore_and_the_task_is_still_restored.
#[test]
fn a_tampered_chain_is_reported_on_restore_and_the_task_is_still_restored() {
    let mut book = process_one();
    assert_eq!(
        restore(&mut book).unwrap(),
        Restored {
            active: 2,
            ..Restored::default()
        },
        "an untouched store restores clean"
    );
    book.tamper(BOB, "t-paused", 1, |e| e.principal = "someone-else".into());
    let out = restore(&mut book).unwrap();
    assert_eq!(out.active, 2, "both tasks are still restored");
    assert_eq!(out.chain_breaks.len(), 1, "exactly one chain failed");
    let (scope, words) = &out.chain_breaks[0];
    assert_eq!(*scope, task_key(BOB, "t-paused"));
    assert!(words.contains("seq 1"), "{words}");
    assert!(
        get(&mut book, BOB, "t-paused", 105).unwrap().is_some(),
        "the task survived; the BREAK is what is reported, not a deletion"
    );
}

/// ENTRIES CUT FROM THE END ARE CAUGHT. Dropping a chain's last events leaves every remaining link
#[test]
fn dropping_the_last_event_is_a_reported_break() {
    let mut book = process_one();
    let held = get(&mut book, BOB, "t-paused", 105).unwrap().unwrap();
    let last = held.next_seq - 1;
    book.rows
        .remove(&(
            KIND_TASK_EVENT.to_string(),
            event_key(BOB, "t-paused", last),
        ))
        .expect("the chain's last event was held");
    let out = restore(&mut book).unwrap();
    assert_eq!(out.active, 2, "both tasks are still restored");
    assert_eq!(out.chain_breaks.len(), 1, "exactly the cut chain is named");
    let (scope, words) = &out.chain_breaks[0];
    assert_eq!(*scope, task_key(BOB, "t-paused"));
    assert!(
        words.contains(&format!("seq {}", last - 1)) && words.contains(&format!("seq {last}")),
        "the break names where the chain ends and what the task row committed: {words}"
    );
    assert!(
        get(&mut book, BOB, "t-paused", 105).unwrap().is_some(),
        "the task survived; the BREAK is what is reported, not a deletion"
    );
}

/// An in-flight task whose WHOLE chain is gone is a cut chain too: its row committed events the
#[test]
fn dropping_every_event_of_an_in_flight_task_is_a_reported_break() {
    let mut book = process_one();
    book.apply(&[Write {
        kind: KIND_TASK_EVENT,
        key: task_key(ALICE, "t-work"),
        value: Vec::new(),
    }]);
    let out = restore(&mut book).unwrap();
    assert_eq!(out.active, 2);
    assert_eq!(
        out.chain_breaks
            .iter()
            .map(|(scope, _)| scope.as_str())
            .collect::<Vec<_>>(),
        [task_key(ALICE, "t-work").as_str()]
    );
}

/// An untouched store still restores clean: a chain whose last event is the one its task row
#[test]
fn a_whole_chain_is_no_break_whatever_its_neighbours() {
    let mut book = process_one();
    submitted(&mut book, ALICE, "t-work2", 100);
    moved_to(&mut book, "t-work2", TaskState::Working, 101);
    moved_to(&mut book, "t-work2", TaskState::InputRequired, 102);
    let out = restore(&mut book).unwrap();
    assert_eq!(out.active, 3);
    assert!(out.chain_breaks.is_empty(), "{:?}", out.chain_breaks);
}

/// Ported from busbar-a2a a2a/tests/taskstore_tests.rs::a_terminal_task_is_counted_on_restore_and_deliberately_not_loaded.
#[test]
fn a_terminal_task_is_counted_on_restore_and_deliberately_not_loaded() {
    let mut book = process_one();
    moved_to(&mut book, "t-work", TaskState::Completed, 110);
    book.tamper(ALICE, "t-work", 1, |e| e.agent_id = "rewritten".into());
    let out = restore(&mut book).unwrap();
    assert_eq!((out.active, out.terminal), (1, 1));
    assert!(
        out.chain_breaks.is_empty(),
        "a terminal task's chain is not read at restore"
    );
    assert!(
        book.value(KIND_TASK, &task_key(ALICE, "t-work")).is_some(),
        "but its durable row is retained for the provenance window"
    );
}

/// Ported from busbar-a2a a2a/tests/taskstore_tests.rs::an_unreadable_row_is_counted_rather_than_silently_dropped.
#[test]
fn an_unreadable_row_is_counted_rather_than_silently_dropped() {
    let mut book = process_one();
    let mut held = get(&mut book, ALICE, "t-work", 110).unwrap().unwrap();
    held.row.state = "nearly-done".to_string();
    book.hold(ALICE, &held);
    let out = restore(&mut book).unwrap();
    assert_eq!(out.unreadable, 1, "the row is COUNTED");
    assert_eq!(out.active, 1, "and the readable one still came back");
}

/// Ported from busbar-a2a a2a/tests/chain_golden.rs::one_undecodable_record_does_not_drop_the_others_on_restore
#[test]
fn one_undecodable_task_row_does_not_drop_the_others_on_restore() {
    let mut book = process_one();
    book.rows.insert(
        (KIND_TASK.to_string(), task_key(ALICE, "garbage")),
        b"{not a task row".to_vec(),
    );
    let out = restore(&mut book).unwrap();
    assert_eq!(out.unreadable, 1);
    assert_eq!(out.active, 2, "the good tasks are still restored");
    assert!(out.chain_breaks.is_empty());
}

/// Ported from busbar-a2a a2a/tests/front_door_chain_tests.rs::editing_a_persisted_event_breaks_the_chain_the_front_door_wrote.
#[test]
fn editing_a_persisted_event_breaks_the_chain_the_front_door_wrote() {
    let mut book = Book::default();
    let mut out = Vec::new();
    open(
        &mut book,
        &step(ALICE, 100),
        row("t1", 100),
        "planner",
        &mut out,
    )
    .unwrap();
    book.apply(&out);
    assert!(
        restore(&mut book).unwrap().chain_breaks.is_empty(),
        "the untampered rows verify first"
    );
    book.tamper(ALICE, "t1", 2, |e| {
        e.agent_id = format!("{}-rewritten", e.agent_id)
    });
    let breaks = restore(&mut book).unwrap().chain_breaks;
    assert_eq!(breaks.len(), 1, "an edited event must not still verify");
    assert_eq!(
        breaks[0].0,
        task_key(ALICE, "t1"),
        "the break names the task whose chain it is"
    );
}

/// The sweep drops an expired task's chain whole: one empty append on the chain's scope, never a
#[test]
fn the_sweep_drops_an_expired_tasks_chain_whole() {
    let mut book = Book::default();
    submitted(&mut book, ALICE, "t1", 100);
    moved_to(&mut book, "t1", TaskState::Completed, 100);
    let mut out = Vec::new();
    retention_sweep(&mut book, 101 + TERMINAL_TTL_SECS, 64, &mut out).unwrap();
    assert!(
        out.is_empty(),
        "an acknowledged transaction is never written again"
    );
    let dropped: Vec<&Write> = book
        .publications
        .last()
        .unwrap()
        .iter()
        .filter(|w| w.kind == KIND_TASK_EVENT)
        .collect();
    assert_eq!(dropped.len(), 1);
    assert_eq!(
        (dropped[0].key.as_str(), dropped[0].value.is_empty()),
        (task_key(ALICE, "t1").as_str(), true)
    );
}

/// B1 RULING 1 (coordinator 2026-10-07): MOVING BYTES BETWEEN CONTEXT, PRINCIPAL AND AGENT BREAKS
#[test]
fn moving_bytes_between_context_principal_and_agent_breaks_verification() {
    let at = |context: &str, principal: &str, agent: &str| TaskEventRow {
        task_id: "t".into(),
        seq: 1,
        ts: 1,
        kind: "task.submitted".into(),
        context_id: context.into(),
        principal: principal.into(),
        agent_id: agent.into(),
        state: "submitted".into(),
        request_id: String::new(),
        prev_hash: String::new(),
        hash: String::new(),
        digest_version: DIGEST_VERSION_LEN_PREFIXED,
    };
    assert_ne!(
        suffix(&at("a|b", "c", "ag")),
        suffix(&at("a", "b|c", "ag")),
        "context and principal: two tuples, two records"
    );
    assert_ne!(
        suffix(&at("a", "b|c", "ag")),
        suffix(&at("a", "b", "c|ag")),
        "principal and agent: two tuples, two records"
    );
    let mut book = Book::default();
    let mut first = row("t1", 100);
    first.context_id = "ctx|a".into();
    let mut out = Vec::new();
    submit(&mut book, &step(ALICE, 100), first, &mut out).unwrap();
    book.apply(&out);
    assert!(restore(&mut book).unwrap().chain_breaks.is_empty());
    book.tamper(ALICE, "t1", 1, |e| {
        e.context_id = "ctx".into();
        e.principal = format!("a|{}", e.principal);
    });
    assert_eq!(
        restore(&mut book).unwrap().chain_breaks.len(),
        1,
        "the moved boundary is an edit, and the host reports it"
    );
}

/// Task record-chain scopes use the caller's opaque reference and task identity without exposing the principal or key id.
#[test]
fn the_chain_scope_is_the_callers_opaque_reference_and_the_task() {
    const PRINCIPAL: &str = "acct:alice@example.com";
    const KEY_ID: &str = "vk_alice";

    let caller_ref = busbar_contract::redacted::sha256_hex(b"keyed digest of the principal");
    let mut book = Book::default();
    let mut out = Vec::new();
    open(
        &mut book,
        &step(&caller_ref, 100),
        row("t1", 100),
        "planner",
        &mut out,
    )
    .unwrap();
    assert!(
        out.is_empty(),
        "an acknowledged transaction is never written again"
    );
    let committed = book.publications.last().unwrap();
    let scopes: Vec<&str> = committed
        .iter()
        .filter(|w| w.kind == KIND_TASK_EVENT)
        .map(|w| w.key.as_str())
        .collect();
    let want = format!("{caller_ref}/t1");
    assert_eq!(
        scopes,
        [want.as_str(), want.as_str()],
        "submitted, delegated"
    );
    for w in committed {
        for leak in [PRINCIPAL, KEY_ID, "alice"] {
            assert!(!w.key.contains(leak), "{} key names {leak}", w.kind);
            assert!(
                !String::from_utf8_lossy(&w.value).contains(leak),
                "{} value names {leak}",
                w.kind
            );
        }
    }
    for raw in [PRINCIPAL, KEY_ID] {
        assert!(
            submit(&mut book, &step(raw, 100), row("t2", 100), &mut Vec::new()).is_err(),
            "{raw} is no caller reference: no task is held under it"
        );
    }
}

/// THE TASK KIND IS TERMINAL-ONLY, and the plane's records layer is what keeps it so. At f608d7d5
#[test]
fn the_records_layer_declares_the_task_kind_as_terminal_only() {
    use crate::records::{retention_of, Retention, HELD_KINDS};
    let rules: Vec<(&str, Retention)> = HELD_KINDS.iter().map(|k| (*k, retention_of(k))).collect();
    assert_eq!(
        rules,
        [
            (KIND_TASK, Retention::TerminalOnly),
            (KIND_TASK_EVENT, Retention::Age),
            (KIND_PUSH_CONFIG, Retention::Age),
            (crate::records::KIND_CARD, Retention::Age),
            (crate::records::KIND_CARD_APPROVAL, Retention::Age),
        ]
    );

    assert!(Retention::TerminalOnly.drops(10, 11, true));
    assert!(!Retention::TerminalOnly.drops(10, 11, false));
    assert!(!Retention::TerminalOnly.drops(11, 11, true));
    assert!(Retention::Age.drops(10, 11, false));
    assert!(!Retention::Age.drops(11, 11, false));

    let mut book = Book::default();
    submitted(&mut book, ALICE, "waiting", 100);
    moved_to(&mut book, "waiting", TaskState::Working, 100);
    moved_to(&mut book, "waiting", TaskState::InputRequired, 100);
    submitted(&mut book, ALICE, "done", 100);
    moved_to(&mut book, "done", TaskState::Completed, 100);
    let now = 100 + 86_400 * 365;
    let mut out = Vec::new();
    retention_sweep(&mut book, now, 64, &mut out).unwrap();
    book.apply(&out);
    assert!(book.value(KIND_TASK, &task_key(ALICE, "done")).is_none());
    assert!(book
        .value(KIND_TASK_EVENT, &event_key(ALICE, "done", 1))
        .is_none());
    let held = get(&mut book, ALICE, "waiting", now).unwrap().unwrap();
    assert_eq!(held.row.state, "input-required", "the active row stays");
    assert!(
        book.value(KIND_TASK_EVENT, &event_key(ALICE, "waiting", 1))
            .is_some(),
        "and its chain with it"
    );

    let before = restore(&mut book).unwrap();
    let mut restarted = book.clone();
    assert_eq!(restore(&mut restarted).unwrap(), before);
    assert_eq!((before.active, before.terminal), (1, 0));
    assert_eq!(
        list(&mut restarted, ALICE, now).unwrap(),
        list(&mut book, ALICE, now).unwrap()
    );
    let mut out = Vec::new();
    retention_sweep(&mut restarted, now, 64, &mut out).unwrap();
    assert!(
        out.is_empty(),
        "a restarted sweep finds nothing more to drop"
    );
}

/// The host records, every `records.list` they answer logged as `(kind, prefix)`.
struct Listed<'b> {
    book: &'b mut Book,
    lists: Vec<(String, String)>,
}

impl Records for Listed<'_> {
    fn get(&mut self, kind: &str, key: &str) -> Result<Option<Vec<u8>>, Halt> {
        self.book.get(kind, key)
    }
    fn list(&mut self, kind: &str, prefix: &str) -> Result<Vec<(String, Vec<u8>)>, Halt> {
        self.lists.push((kind.to_string(), prefix.to_string()));
        self.book.list(kind, prefix)
    }
    fn claim(&mut self, kind: &str, key: &str, ttl_ms: u64) -> Result<bool, Halt> {
        self.book.claim(kind, key, ttl_ms)
    }
}

/// THE RESTORE READS ONLY THE IN-FLIGHT TASKS' CHAINS: each one listed under its own scope, and a
#[test]
fn the_restore_reads_only_the_in_flight_tasks_chains() {
    let mut book = process_one();
    moved_to(&mut book, "t-work", TaskState::Completed, 110);
    let mut listed = Listed {
        book: &mut book,
        lists: Vec::new(),
    };
    let out = restore(&mut listed).unwrap();
    assert_eq!((out.active, out.terminal), (1, 1));
    let chains: Vec<&str> = listed
        .lists
        .iter()
        .filter(|(kind, _)| kind == KIND_TASK_EVENT)
        .map(|(_, prefix)| prefix.as_str())
        .collect();
    assert_eq!(chains, [task_key(BOB, "t-paused").as_str()]);
}
