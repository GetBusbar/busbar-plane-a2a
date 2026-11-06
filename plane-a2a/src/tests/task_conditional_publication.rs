// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::cell::RefCell;
use std::rc::Rc;

use super::*;

#[path = "task_quota_tests.rs"]
mod task_quota_tests;

#[derive(Clone, Debug, PartialEq, Eq)]
struct Candidate {
    predicates: Vec<Predicate>,
    chains: Vec<ChainLife>,
    writes: Vec<Write>,
}

#[derive(Clone)]
enum Answer {
    Get(Option<Vec<u8>>),
    List(Vec<(String, Vec<u8>)>),
    Life(Option<Vec<u8>>),
    Publish(Candidate, Option<bool>),
    QuotaRetry,
}

/// A callback's replayed host handles and its explicitly driven conditional exchange. Keeping the
/// candidate and host receipt separate lets a test lose a commit reply without redoing it.
type ReadInterleaving = (String, String, fn(&mut Book));

struct Call {
    host: Rc<RefCell<Book>>,
    answers: Vec<Answer>,
    cursor: usize,
    pending: Option<usize>,
    committed: BTreeMap<usize, bool>,
    unsupported: bool,
    before_get: Option<ReadInterleaving>,
    quota_retry: crate::conditional_publication::Journal,
    quota_now_ns: Option<u64>,
}

impl Call {
    fn new(host: &Rc<RefCell<Book>>) -> Self {
        Self {
            host: host.clone(),
            answers: Vec::new(),
            cursor: 0,
            pending: None,
            committed: BTreeMap::new(),
            unsupported: false,
            before_get: None,
            quota_retry: crate::conditional_publication::Journal::default(),
            quota_now_ns: None,
        }
    }

    fn replay(&mut self) {
        self.cursor = 0;
    }

    fn index(&mut self) -> usize {
        let index = self.cursor;
        self.cursor += 1;
        index
    }

    fn offered(&self) -> &Candidate {
        match &self.answers[self.pending.unwrap()] {
            Answer::Publish(candidate, _) => candidate,
            _ => unreachable!(),
        }
    }

    fn commit(&mut self, deliver_receipt: bool) -> bool {
        let index = self.pending.unwrap();
        let applied = match self.committed.get(&index) {
            Some(applied) => *applied,
            None => {
                let candidate = self.offered().clone();
                let applied = self
                    .host
                    .borrow_mut()
                    .publish(&candidate.predicates, &candidate.chains, &candidate.writes)
                    .unwrap();
                self.committed.insert(index, applied);
                applied
            }
        };
        if deliver_receipt {
            let Answer::Publish(_, receipt) = &mut self.answers[index] else {
                unreachable!()
            };
            *receipt = Some(applied);
            self.pending = None;
        }
        applied
    }
}

impl Records for Call {
    fn retry_quota(&mut self) -> Result<bool, Halt> {
        let index = self.index();
        if index == self.answers.len() {
            self.answers.push(Answer::QuotaRetry);
        }
        assert!(matches!(self.answers[index], Answer::QuotaRetry));
        let seq = u32::try_from(index).unwrap();
        self.quota_retry.retry_quota(
            seq,
            self.quota_now_ns
                .unwrap_or(self.committed.len() as u64 * 1_000_000),
        )
    }

    fn quota_bootstrap_allowed(&mut self) -> Result<bool, Halt> {
        self.host.borrow_mut().quota_bootstrap_allowed()
    }
    fn get(&mut self, kind: &str, key: &str) -> Result<Option<Vec<u8>>, Halt> {
        if self
            .before_get
            .as_ref()
            .is_some_and(|(k, wanted, _)| k == kind && wanted == key)
        {
            let (_, _, interleave) = self.before_get.take().unwrap();
            interleave(&mut self.host.borrow_mut());
        }
        let index = self.index();
        if index == self.answers.len() {
            self.answers
                .push(Answer::Get(self.host.borrow_mut().get(kind, key)?));
        }
        match &self.answers[index] {
            Answer::Get(value) => Ok(value.clone()),
            _ => panic!("the callback changed its host handle sequence"),
        }
    }

    fn list(&mut self, kind: &str, prefix: &str) -> Result<Vec<(String, Vec<u8>)>, Halt> {
        let index = self.index();
        if index == self.answers.len() {
            self.answers
                .push(Answer::List(self.host.borrow_mut().list(kind, prefix)?));
        }
        match &self.answers[index] {
            Answer::List(value) => Ok(value.clone()),
            _ => panic!("the callback changed its host handle sequence"),
        }
    }

    fn observe_chain_life(&mut self, kind: &str, scope: &str) -> Result<Option<Vec<u8>>, Halt> {
        if self.unsupported {
            return Err(Halt::Failed("conditional capability unavailable".into()));
        }
        let index = self.index();
        if index == self.answers.len() {
            self.answers.push(Answer::Life(
                self.host.borrow_mut().observe_chain_life(kind, scope)?,
            ));
        }
        match &self.answers[index] {
            Answer::Life(value) => Ok(value.clone()),
            _ => panic!("the callback changed its host handle sequence"),
        }
    }

    fn publish(
        &mut self,
        predicates: &[Predicate],
        chains: &[ChainLife],
        writes: &[Write],
    ) -> Result<bool, Halt> {
        let candidate = Candidate {
            predicates: predicates.to_vec(),
            chains: chains.to_vec(),
            writes: writes.to_vec(),
        };
        let index = self.index();
        if index == self.answers.len() {
            self.answers.push(Answer::Publish(candidate.clone(), None));
        }
        match &self.answers[index] {
            Answer::Publish(original, receipt) => {
                assert_eq!(
                    original, &candidate,
                    "unknown outcomes replay exact candidate bytes"
                );
                match receipt {
                    Some(applied) => Ok(*applied),
                    None => {
                        self.pending = Some(index);
                        Err(Halt::Pending)
                    }
                }
            }
            _ => panic!("the callback changed its host handle sequence"),
        }
    }
}

fn active() -> Rc<RefCell<Book>> {
    let mut book = Book::default();
    submitted(&mut book, ALICE, "task", 100);
    Rc::new(RefCell::new(book))
}

fn expired_task() -> Rc<RefCell<Book>> {
    let host = active();
    moved_to(&mut host.borrow_mut(), "task", TaskState::Completed, 100);
    host.borrow_mut().apply(&[Write {
        kind: KIND_PUSH_CONFIG,
        key: task_key(ALICE, "task"),
        value: b"original callback credentials".to_vec(),
    }]);
    host
}

fn bump(call: &mut Call) -> Result<Option<TaskRow>, Halt> {
    let mut out = Vec::new();
    let result = bump_cursor(call, &step(ALICE, 200), "task", &mut out);
    assert!(
        out.is_empty(),
        "guarded records never escape as ordinary writes"
    );
    result
}

#[test]
fn two_writers_wait_for_ack_and_the_loser_replans_on_fresh_handles() {
    let host = active();
    let original = host.borrow().clone();
    let mut first = Call::new(&host);
    let mut second = Call::new(&host);
    assert_eq!(bump(&mut first), Err(Halt::Pending));
    assert_eq!(bump(&mut second), Err(Halt::Pending));
    assert_eq!(
        *host.borrow(),
        original,
        "unsubmitted candidates claim and publish nothing"
    );
    assert!(first.commit(true));
    assert!(!second.commit(true));
    second.replay();
    assert_eq!(bump(&mut second), Err(Halt::Pending));
    assert!(second.commit(true));
    second.replay();
    assert_eq!(bump(&mut second).unwrap().unwrap().artifact_cursor, 2);
    first.replay();
    assert_eq!(bump(&mut first).unwrap().unwrap().artifact_cursor, 1);
    let held = get(&mut *host.borrow_mut(), ALICE, "task", 200)
        .unwrap()
        .unwrap();
    assert_eq!((held.row.artifact_cursor, held.next_seq), (2, 4));
    assert!(restore(&mut *host.borrow_mut())
        .unwrap()
        .chain_breaks
        .is_empty());
}

#[test]
fn lost_applied_reply_replays_original_attempt_without_a_second_append() {
    let host = active();
    let mut call = Call::new(&host);
    assert_eq!(bump(&mut call), Err(Halt::Pending));
    let original = call.offered().clone();
    assert!(call.commit(false));
    let committed = host.borrow().clone();
    call.replay();
    assert_eq!(bump(&mut call), Err(Halt::Pending));
    assert_eq!(call.offered(), &original);
    assert!(call.commit(true));
    call.replay();
    assert_eq!(bump(&mut call).unwrap().unwrap().artifact_cursor, 1);
    assert_eq!(*host.borrow(), committed);
}

#[test]
fn abandoned_presubmit_candidate_and_old_claim_do_not_block_retention() {
    let host = expired_task();
    let mut abandoned = Call::new(&host);
    let mut out = Vec::new();
    assert_eq!(
        record_push_delivery(
            &mut abandoned,
            &step(ALICE, 200),
            "task",
            "push.delivered",
            &mut out
        ),
        Err(Halt::Pending)
    );
    let next = get(&mut *host.borrow_mut(), ALICE, "task", 200)
        .unwrap()
        .unwrap()
        .next_seq;
    assert!(host
        .borrow_mut()
        .claim(
            KIND_TASK_EVENT,
            &event_key(ALICE, "task", next),
            CLAIM_TTL_MS
        )
        .unwrap());
    drop(abandoned);
    assert_eq!(
        retention_sweep(&mut *host.borrow_mut(), 401, 1, &mut out).unwrap(),
        1
    );
    assert!(host
        .borrow()
        .value(KIND_TASK, &task_key(ALICE, "task"))
        .is_none());
    assert!(host
        .borrow()
        .value(KIND_PUSH_CONFIG, &task_key(ALICE, "task"))
        .is_none());
    assert!(host
        .borrow_mut()
        .list(KIND_TASK_EVENT, &task_key(ALICE, "task"))
        .unwrap()
        .is_empty());
}

#[test]
fn writer_and_retention_commit_in_either_order_without_resurrection_or_chain_loss() {
    for writer_first in [true, false] {
        let host = expired_task();
        let mut writer = Call::new(&host);
        let mut retirement = Call::new(&host);
        let mut out = Vec::new();
        assert_eq!(
            record_push_delivery(
                &mut writer,
                &step(ALICE, 200),
                "task",
                "push.delivered",
                &mut out
            ),
            Err(Halt::Pending)
        );
        assert_eq!(
            retention_sweep(&mut retirement, 401, 1, &mut out),
            Err(Halt::Pending)
        );
        if writer_first {
            assert!(writer.commit(true));
            assert!(!retirement.commit(true));
            retirement.replay();
            assert_eq!(
                retention_sweep(&mut retirement, 401, 1, &mut out).unwrap(),
                0
            );
            assert_eq!(
                host.borrow_mut()
                    .list(KIND_TASK_EVENT, &task_key(ALICE, "task"))
                    .unwrap()
                    .len(),
                3
            );
        } else {
            assert!(retirement.commit(true));
            assert!(!writer.commit(true));
            writer.replay();
            assert!(matches!(
                record_push_delivery(
                    &mut writer,
                    &step(ALICE, 200),
                    "task",
                    "push.delivered",
                    &mut out
                ),
                Err(Halt::Failed(_))
            ));
            assert!(host
                .borrow()
                .value(KIND_TASK, &task_key(ALICE, "task"))
                .is_none());
            assert!(host
                .borrow_mut()
                .list(KIND_TASK_EVENT, &task_key(ALICE, "task"))
                .unwrap()
                .is_empty());
        }
        assert!(out.is_empty());
    }
}

#[test]
fn exact_raw_row_bytes_are_compared_without_json_reserialization() {
    let host = active();
    let key = task_key(ALICE, "task");
    let mut raw = host.borrow().value(KIND_TASK, &key).unwrap().clone();
    raw.splice(0..0, b" \n".iter().copied());
    host.borrow_mut()
        .rows
        .insert((KIND_TASK.to_string(), key), raw.clone());
    let mut call = Call::new(&host);
    assert_eq!(bump(&mut call), Err(Halt::Pending));
    assert_eq!(call.offered().predicates[0].expected, Some(raw));
    assert!(call.commit(true));
    call.replay();
    assert!(bump(&mut call).is_ok());
}

#[test]
fn pending_creation_is_one_atomic_final_row_with_both_events() {
    let host = Rc::new(RefCell::new(Book::default()));
    let mut call = Call::new(&host);
    let mut out = Vec::new();
    assert_eq!(
        open(
            &mut call,
            &step(ALICE, 100),
            row("task", 100),
            "planner",
            &mut out
        ),
        Err(Halt::Pending)
    );
    assert!(host
        .borrow()
        .rows
        .keys()
        .all(|(kind, _)| kind == crate::records::KIND_TASK_QUOTA));
    assert_eq!(
        call.offered()
            .writes
            .iter()
            .filter(|w| w.kind == KIND_TASK_EVENT)
            .count(),
        2
    );
    assert!(call.commit(true));
    call.replay();
    assert_eq!(
        open(
            &mut call,
            &step(ALICE, 100),
            row("task", 100),
            "planner",
            &mut out
        )
        .unwrap()
        .agent_id,
        "planner"
    );
    assert_eq!(
        get(&mut *host.borrow_mut(), ALICE, "task", 100)
            .unwrap()
            .unwrap()
            .next_seq,
        3
    );
    assert!(out.is_empty());
}

#[test]
fn missing_capability_refuses_before_reads_publication_or_claims() {
    let host = active();
    let original = host.borrow().clone();
    let mut call = Call::new(&host);
    call.unsupported = true;
    assert!(matches!(bump(&mut call), Err(Halt::Failed(_))));
    assert!(call.answers.is_empty());
    assert_eq!(*host.borrow(), original);
}

#[test]
fn stale_incarnation_cannot_append_or_install_config_after_identical_recreation() {
    for config_only in [true, false] {
        let host = active();
        let original = host
            .borrow()
            .value(KIND_TASK, &task_key(ALICE, "task"))
            .unwrap()
            .clone();
        let mut call = Call::new(&host);
        let result = if config_only {
            write_config(
                &mut call,
                &step(ALICE, 200),
                "task",
                None,
                b"old secret".to_vec(),
            )
            .map(|_| None)
        } else {
            bump(&mut call)
        };
        assert_eq!(result, Err(Halt::Pending));
        let mut book = host.borrow_mut();
        let chain = observe(&mut *book, &task_key(ALICE, "task")).unwrap();
        assert!(forget(&mut *book, &task_key(ALICE, "task"), &original, chain).unwrap());
        submitted(&mut book, ALICE, "task", 100);
        assert_eq!(
            book.value(KIND_TASK, &task_key(ALICE, "task")),
            Some(&original)
        );
        drop(book);
        assert!(
            !call.commit(true),
            "matching JSON from a replacement does not refresh old life"
        );
        assert!(host
            .borrow()
            .value(KIND_PUSH_CONFIG, &task_key(ALICE, "task"))
            .is_none());
        assert_eq!(
            host.borrow_mut()
                .list(KIND_TASK_EVENT, &task_key(ALICE, "task"))
                .unwrap()
                .len(),
            1
        );
    }
}

#[test]
fn incarnation_is_observed_before_the_fresh_task_read_not_at_submission() {
    let host = active();
    let key = task_key(ALICE, "task");
    let mut call = Call::new(&host);
    assert_eq!(
        call.observe_chain_life(KIND_TASK_EVENT, &key).unwrap(),
        None
    );
    {
        let mut book = host.borrow_mut();
        let raw = book.value(KIND_TASK, &key).unwrap().clone();
        let chain = observe(&mut *book, &key).unwrap();
        assert!(forget(&mut *book, &key, &raw, chain).unwrap());
        submitted(&mut book, ALICE, "task", 100);
    }

    call.replay();
    assert_eq!(bump(&mut call), Err(Halt::Pending));
    assert_eq!(call.offered().chains[0].expected, None);
    assert!(!call.commit(true));
    assert_eq!(
        get(&mut *host.borrow_mut(), ALICE, "task", 200)
            .unwrap()
            .unwrap()
            .row
            .artifact_cursor,
        0
    );
}

#[test]
fn config_replacement_and_retirement_never_leave_a_config_without_its_task() {
    for config_first in [true, false] {
        let host = expired_task();
        let old = host
            .borrow()
            .value(KIND_PUSH_CONFIG, &task_key(ALICE, "task"))
            .cloned();
        let mut config = Call::new(&host);
        let mut retirement = Call::new(&host);
        assert_eq!(
            write_config(
                &mut config,
                &step(ALICE, 200),
                "task",
                old,
                b"replacement credentials".to_vec()
            ),
            Err(Halt::Pending)
        );
        assert_eq!(
            retention_sweep(&mut retirement, 401, 1, &mut Vec::new()),
            Err(Halt::Pending)
        );
        if config_first {
            assert!(config.commit(true));
            assert!(retirement.commit(true));
        } else {
            assert!(retirement.commit(true));
            assert!(!config.commit(true));
        }
        let book = host.borrow();
        assert!(book.value(KIND_TASK, &task_key(ALICE, "task")).is_none());
        assert!(book
            .value(KIND_PUSH_CONFIG, &task_key(ALICE, "task"))
            .is_none());
    }
}

#[test]
fn replay_of_applied_retirement_after_recreation_does_not_drop_the_new_chain() {
    let host = expired_task();
    let mut retirement = Call::new(&host);
    assert_eq!(
        retention_sweep(&mut retirement, 401, 1, &mut Vec::new()),
        Err(Halt::Pending)
    );
    assert!(retirement.commit(false));
    submitted(&mut host.borrow_mut(), ALICE, "task", 500);
    let recreated = host.borrow().clone();
    retirement.replay();
    assert_eq!(
        retention_sweep(&mut retirement, 401, 1, &mut Vec::new()),
        Err(Halt::Pending)
    );
    assert!(retirement.commit(true));
    retirement.replay();
    assert_eq!(
        retention_sweep(&mut retirement, 401, 1, &mut Vec::new()).unwrap(),
        1
    );
    assert_eq!(*host.borrow(), recreated);
}

#[test]
fn fresh_open_and_resume_publish_the_inline_config_with_the_task_events() {
    let host = Rc::new(RefCell::new(Book::default()));
    let mut call = Call::new(&host);
    let config = b"callback credential".to_vec();
    assert_eq!(
        open_configured(
            &mut call,
            &step(ALICE, 100),
            row("task", 100),
            "planner",
            Some(config.clone())
        ),
        Err(Halt::Pending)
    );
    assert!(host
        .borrow()
        .rows
        .keys()
        .all(|(kind, _)| kind == crate::records::KIND_TASK_QUOTA));
    assert_eq!(
        call.offered()
            .writes
            .iter()
            .filter(|w| w.kind != crate::records::KIND_TASK_QUOTA)
            .count(),
        4
    );
    assert!(call.commit(true));
    call.replay();
    assert!(open_configured(
        &mut call,
        &step(ALICE, 100),
        row("task", 100),
        "planner",
        Some(config.clone())
    )
    .is_ok());
    assert_eq!(
        host.borrow()
            .value(KIND_PUSH_CONFIG, &task_key(ALICE, "task")),
        Some(&config)
    );
    moved_to(&mut host.borrow_mut(), "task", TaskState::Working, 110);
    moved_to(
        &mut host.borrow_mut(),
        "task",
        TaskState::InputRequired,
        120,
    );
    let mut resume = Call::new(&host);
    let mut plan = |row: &TaskRow| plan_transition(TaskState::Working, 130)(row).map(Some);
    assert_eq!(
        change_configured(
            &mut resume,
            &step(ALICE, 130),
            "task",
            &mut plan,
            Some(b"new credential")
        ),
        Err(Halt::Pending)
    );
    assert_eq!(
        get(&mut *host.borrow_mut(), ALICE, "task", 130)
            .unwrap()
            .unwrap()
            .row
            .state,
        "input-required"
    );
    assert_eq!(
        host.borrow()
            .value(KIND_PUSH_CONFIG, &task_key(ALICE, "task")),
        Some(&config)
    );
    assert!(resume.commit(true));
    resume.replay();
    assert_eq!(
        change_configured(
            &mut resume,
            &step(ALICE, 130),
            "task",
            &mut plan,
            Some(b"new credential")
        )
        .unwrap()
        .unwrap()
        .state,
        "working"
    );
    assert_eq!(
        host.borrow()
            .value(KIND_PUSH_CONFIG, &task_key(ALICE, "task"))
            .unwrap()
            .as_slice(),
        b"new credential"
    );
}
