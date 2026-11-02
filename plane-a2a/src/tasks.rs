// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The task store, over host records. The plane holds no store: it reads through `records.get` /

use busbar_contract::vocab::{EV_ARTIFACT, EV_DELEGATED, EV_SUBMITTED};
use serde::{Deserialize, Serialize};

use crate::a2a::task::{plan_transition, readable_row, TaskState};
use crate::record::DIGEST_VERSION_LEN_PREFIXED;
use crate::records::{retention_of, KIND_PUSH_CONFIG, KIND_TASK, KIND_TASK_EVENT};
use crate::{TaskEventRow, TaskRow};

/// How long a terminal task stays readable after its terminal transition, in seconds.
pub const TERMINAL_TTL_SECS: u64 = 300;
/// The most terminal tasks kept; past it the oldest go first. An active task is never counted
pub const MAX_RETAINED: usize = 4096;
/// The existing replay-token TTL, retained for legacy claim callers. Task publication and
#[cfg(test)]
pub const CLAIM_TTL_MS: u64 = 60_000;
/// How many times a change rereads after a definitive atomic condition conflict.
const TRIES: usize = 3;
/// The most settled tasks one submit's [`retention_sweep`] retires: a submit opens one task, so a
pub const SWEEP_BUDGET: usize = 32;

/// How long a sweep that left nothing behind holds off the next one, in seconds: the sweep reads
pub const SWEEP_INTERVAL_SECS: u64 = 30;

/// WHEN THE NEXT [`retention_sweep`] IS DUE, per instance: at once while the last one spent its
/// whole budget (more may wait), else [`SWEEP_INTERVAL_SECS`] after it. Plane memory; a restart
/// sweeps on its first submit.
#[derive(Debug, Default)]
pub struct SweepGate {
    last: busbar_contract::abi::sdk::publish::Keyed<(), (u64, bool)>,
}

impl SweepGate {
    /// Whether a submit at `now` sweeps.
    #[must_use]
    pub fn due(&self, now: u64) -> bool {
        self.last.with_all(|m| {
            m.get(&()).is_none_or(|(at, backlog)| {
                *backlog || now >= at.saturating_add(SWEEP_INTERVAL_SECS)
            })
        })
    }

    /// A sweep at `now` retired `touched` tasks of its `budget`.
    pub fn swept(&self, now: u64, touched: usize, budget: usize) {
        self.last
            .with_all(|m| m.insert((), (now, touched >= budget)));
    }
}

/// Why a step on the records did not finish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Halt {
    /// A records call pends: the op answers PENDING and runs again from the top.
    Pending,
    /// The host failed the call, or the change could not be made; the words say which.
    Failed(String),
}

/// The host records as the store reaches them. Every call is made in the same order on every entry
pub trait Records {
    /// The record of `kind` under `key`; `None` when absent or a tombstone.
    fn get(&mut self, kind: &str, key: &str) -> Result<Option<Vec<u8>>, Halt>;
    /// Every live record of `kind` whose key starts with `prefix`, in key order.
    fn list(&mut self, kind: &str, prefix: &str) -> Result<Vec<(String, Vec<u8>)>, Halt>;
    /// Put `key` of `kind` if absent, for `ttl_ms`: `true` when this call made the claim.
    #[cfg(test)]
    fn claim(&mut self, kind: &str, key: &str, ttl_ms: u64) -> Result<bool, Halt>;

    /// Compare every predicate and publish all writes in one host transaction. `true` means
    fn publish(
        &mut self,
        _predicates: &[Predicate],
        _chains: &[ChainLife],
        _writes: &[Write],
    ) -> Result<bool, Halt> {
        Err(Halt::Failed(
            "conditional record publication unavailable".into(),
        ))
    }

    /// Observe the chain incarnation before reading the task for a mutation. Replayed reads
    fn observe_chain_life(&mut self, _kind: &str, _scope: &str) -> Result<Option<Vec<u8>>, Halt> {
        Err(Halt::Failed(
            "conditional chain observation unavailable".into(),
        ))
    }
}

/// An exact pre-state comparison. Bytes come directly from the host, without reserialization.
#[derive(Clone, PartialEq, Eq)]
pub struct Predicate {
    /// The declared record kind.
    pub kind: &'static str,
    /// The existing logical key, including its caller scope.
    pub key: String,
    /// Exact existing bytes, or absence.
    pub expected: Option<Vec<u8>>,
}

impl Drop for Predicate {
    fn drop(&mut self) {
        if let Some(bytes) = &mut self.expected {
            crate::record_custody::bytes(bytes);
        }
    }
}

impl std::fmt::Debug for Predicate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Predicate")
            .field("kind", &self.kind)
            .field("key", &self.key)
            .field("expected", &"[REDACTED]")
            .finish()
    }
}

/// The original incarnation of a chain, observed before the task bytes used by a plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainLife {
    /// The declared chained kind.
    pub kind: &'static str,
    /// The existing caller/task chain scope.
    pub scope: String,
    /// Exact host life bytes, or absence for a chain with no recorded incarnation yet.
    pub expected: Option<Vec<u8>>,
}

fn observe(rec: &mut dyn Records, key: &str) -> Result<ChainLife, Halt> {
    Ok(ChainLife {
        kind: KIND_TASK_EVENT,
        scope: key.to_string(),
        expected: rec.observe_chain_life(KIND_TASK_EVENT, key)?,
    })
}

/// THE RECORDS AS ONE PIECE SEES THEM ONCE IT HAS WRITTEN: a read of a record the piece already
pub struct Staged<'r> {
    rec: &'r mut dyn Records,
    written: &'r [Write],
}

impl<'r> Staged<'r> {
    /// `rec`, seen through the `written` writes of the piece so far.
    pub fn new(rec: &'r mut dyn Records, written: &'r [Write]) -> Self {
        Self { rec, written }
    }
}

/// Whether `kind` is the chained kind: its writes are appends the host seals once the store took
fn chained(kind: &str) -> bool {
    kind == KIND_TASK_EVENT
}

impl Records for Staged<'_> {
    fn get(&mut self, kind: &str, key: &str) -> Result<Option<Vec<u8>>, Halt> {
        match self
            .written
            .iter()
            .rev()
            .find(|w| !chained(w.kind) && w.kind == kind && w.key == key)
        {
            Some(w) if w.value.is_empty() => Ok(None),
            Some(w) => Ok(Some(w.value.clone())),
            None => self.rec.get(kind, key),
        }
    }

    fn list(&mut self, kind: &str, prefix: &str) -> Result<Vec<(String, Vec<u8>)>, Halt> {
        let mut listed = crate::proto::custody::Guard::new(
            self.rec
                .list(kind, prefix)?
                .into_iter()
                .collect::<std::collections::BTreeMap<String, Vec<u8>>>(),
        );
        for w in self
            .written
            .iter()
            .filter(|w| !chained(w.kind) && w.kind == kind && w.key.starts_with(prefix))
        {
            if w.value.is_empty() {
                drop(listed.remove(&w.key).map(crate::relay::RawBytes::from));
            } else {
                drop(
                    listed
                        .insert(w.key.clone(), w.value.clone())
                        .map(crate::relay::RawBytes::from),
                );
            }
        }
        Ok(listed.take().into_iter().collect())
    }

    #[cfg(test)]
    fn claim(&mut self, kind: &str, key: &str, ttl_ms: u64) -> Result<bool, Halt> {
        self.rec.claim(kind, key, ttl_ms)
    }

    fn publish(
        &mut self,
        predicates: &[Predicate],
        chains: &[ChainLife],
        writes: &[Write],
    ) -> Result<bool, Halt> {
        self.rec.publish(predicates, chains, writes)
    }

    fn observe_chain_life(&mut self, kind: &str, scope: &str) -> Result<Option<Vec<u8>>, Halt> {
        self.rec.observe_chain_life(kind, scope)
    }
}

/// One record write the answer carries out: a `RECORD_PUT`; an empty value is a tombstone. On the
/// chained kind it is an append to the chain `key` names (an empty value drops the chain).
#[derive(Clone, PartialEq, Eq)]
pub struct Write {
    /// The record kind.
    pub kind: &'static str,
    /// The key.
    pub key: String,
    /// The value; empty = tombstone.
    pub value: Vec<u8>,
}

impl Drop for Write {
    fn drop(&mut self) {
        crate::record_custody::bytes(&mut self.value);
    }
}

impl std::fmt::Debug for Write {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Write")
            .field("kind", &self.kind)
            .field("key", &self.key)
            .field("value", &"[REDACTED]")
            .finish()
    }
}

/// A TASK AS IT IS HELD: the row, and the sequence its chain's next event takes (the host holds the
/// chain itself; the sequence is what a change claims).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeldTask {
    /// The row.
    #[serde(flatten)]
    pub row: TaskRow,
    /// The sequence the next event takes.
    pub next_seq: u64,
}

/// The key prefix of everything `caller` holds.
fn scope(caller: &str) -> String {
    format!("{caller}/")
}

/// The key of `caller`'s task `task`.
#[must_use]
pub fn task_key(caller: &str, task: &str) -> String {
    format!("{caller}/{task}")
}

/// The key of event `seq` of `caller`'s task `task`: the host's listed key of record `seq` of the
#[must_use]
#[cfg(test)]
pub fn event_key(caller: &str, task: &str, seq: u64) -> String {
    format!("{caller}/{task}/{seq:020}")
}

/// Whether `caller` is a reference a key may start with: non-empty lower-case hex.
#[must_use]
pub fn is_caller(caller: &str) -> bool {
    !caller.is_empty()
        && caller
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Whether `state` is a terminal task-state token.
fn terminal(state: &str) -> bool {
    TaskState::parse(state).is_ok_and(TaskState::is_terminal)
}

/// The cutoff of the task kind's purge at `now`: a row unchanged since before it is past its
fn cutoff(now: u64) -> u64 {
    now.saturating_sub(TERMINAL_TTL_SECS)
}

/// Whether a held task is past its window at `now`: the task kind's rule
#[must_use]
pub fn expired(row: &TaskRow, now: u64) -> bool {
    retention_of(KIND_TASK).drops(row.updated_at, cutoff(now), terminal(&row.state))
}

fn decode(bytes: &[u8]) -> Option<HeldTask> {
    serde_json::from_slice(bytes).ok()
}

fn encode<T: Serialize>(v: &T) -> Result<Vec<u8>, Halt> {
    serde_json::to_vec(v).map_err(|e| Halt::Failed(e.to_string()))
}

/// One event's own bytes on its task's chain, in the declared length-prefixed framing: `ts` (its eight big-endian bytes), `kind`, `context_id`,
#[must_use]
pub fn suffix(ev: &TaskEventRow) -> Vec<u8> {
    let mut out = Vec::new();
    let mut field = |bytes: &[u8]| {
        out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
        out.extend_from_slice(bytes);
    };
    field(&ev.ts.to_be_bytes());
    for text in [
        &ev.kind,
        &ev.context_id,
        &ev.principal,
        &ev.agent_id,
        &ev.state,
    ] {
        field(text.as_bytes());
    }
    out
}

/// Event `kind` over `row` at `held`'s chain position, stamped `ts`; its chain fields are the
fn seal_event(
    held: &HeldTask,
    row: &TaskRow,
    kind: &str,
    request_id: &str,
    ts: u64,
) -> TaskEventRow {
    TaskEventRow {
        task_id: row.task_id.clone(),
        seq: held.next_seq,
        ts,
        kind: kind.to_string(),
        context_id: row.context_id.clone(),
        principal: row.principal.clone(),
        agent_id: row.agent_id.clone(),
        state: row.state.clone(),
        request_id: request_id.to_string(),
        prev_hash: String::new(),
        hash: String::new(),
        digest_version: DIGEST_VERSION_LEN_PREFIXED,
    }
}

/// `caller`'s task `task` as held, or `None`: absent, another caller's, unreadable, or past its
pub fn get(
    rec: &mut dyn Records,
    caller: &str,
    task: &str,
    now: u64,
) -> Result<Option<HeldTask>, Halt> {
    if !is_caller(caller) {
        return Ok(None);
    }
    Ok(rec
        .get(KIND_TASK, &task_key(caller, task))?
        .and_then(|b| decode(&b))
        .filter(|h| !expired(&h.row, now)))
}

/// Every task `caller` holds at `now`, by task id.
pub fn list(rec: &mut dyn Records, caller: &str, now: u64) -> Result<Vec<TaskRow>, Halt> {
    if !is_caller(caller) {
        return Ok(Vec::new());
    }
    let mut rows: Vec<TaskRow> = rec
        .list(KIND_TASK, &scope(caller))?
        .into_iter()
        .filter_map(|(_, b)| decode(&b))
        .map(|h| h.row)
        .filter(|r| !expired(r, now))
        .collect();
    rows.sort_by(|a, b| a.task_id.cmp(&b.task_id));
    Ok(rows)
}

/// What a [`restore`] found: the boot rehydrate counts, over the records.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Restored {
    /// Tasks in flight: their chains were read back verified.
    pub active: usize,
    /// Terminal tasks: counted, their chains not read back (nothing resumes them, and their rows
    /// stay for the provenance window).
    pub terminal: usize,
    /// Task rows this build cannot read back: counted, never skipped silently.
    pub unreadable: usize,
    /// The in-flight tasks whose chain the host reported broken: the chain's scope
    /// (`<caller>/<task>`) and the break in the host's words. The task is still held: a break is
    /// reported, never a deletion.
    pub chain_breaks: Vec<(String, String)>,
}

/// The restore, over host records: every task row read and
pub fn restore(rec: &mut dyn Records) -> Result<Restored, Halt> {
    let mut out = Restored::default();
    let mut active = Vec::new();
    for (key, bytes) in rec.list(KIND_TASK, "")? {
        let Some(held) = decode(&bytes).filter(|h| readable_row(&h.row).is_ok()) else {
            out.unreadable += 1;
            continue;
        };
        if terminal(&held.row.state) {
            out.terminal += 1;
        } else {
            out.active += 1;
            active.push((key, held.next_seq));
        }
    }
    for (chain_scope, next_seq) in active {
        let listed = rec.list(KIND_TASK_EVENT, &chain_scope)?;
        if let Some((_, words)) = listed.iter().find(|(key, _)| *key == chain_scope) {
            out.chain_breaks
                .push((chain_scope, String::from_utf8_lossy(words).into_owned()));
            continue;
        }

        let reached = listed
            .iter()
            .filter_map(|(key, _)| busbar_contract::services::chain_key_parts(key.as_bytes()))
            .filter(|(chain, _)| *chain == chain_scope.as_bytes())
            .map(|(_, seq)| seq)
            .max()
            .unwrap_or(0);
        let committed = next_seq.saturating_sub(1);
        if reached < committed {
            let words = format!(
                "the chain for scope `{chain_scope}` ends at seq {reached}, but its task row committed \
                 events through seq {committed}: entries are missing from the chain's end (cut \
                 from it, or never written to it)"
            );
            out.chain_breaks.push((chain_scope, words));
        }
    }
    Ok(out)
}

/// Who writes, its correlation reference, and when: what each task change is stamped with.
#[derive(Debug, Clone, Copy)]
pub struct Stamp<'a> {
    /// The caller's reference: the key prefix.
    pub caller: &'a str,
    /// The correlation reference recorded as `TaskEventRow.request_id`; current
    /// task-hop callers supply their task id. This is not a JSON-RPC envelope id.
    pub request_id: &'a str,
    /// Now, in seconds: the event's stamp.
    pub now: u64,
}

/// Compare the exact prior bytes and atomically publish the next task row and its event.
fn commit(
    rec: &mut dyn Records,
    at: &Stamp<'_>,
    held: &HeldTask,
    observed: (Option<Vec<u8>>, ChainLife),
    row: TaskRow,
    kind: &str,
    config: Option<(Option<Vec<u8>>, Vec<u8>)>,
) -> Result<Option<HeldTask>, Halt> {
    let mut config = crate::proto::custody::Guard::new(config);
    let (expected, chain) = observed;
    let expected = expected.map(crate::relay::RawBytes::from);
    let ev = seal_event(held, &row, kind, at.request_id, at.now);
    let next = HeldTask {
        next_seq: held
            .next_seq
            .checked_add(1)
            .ok_or_else(|| Halt::Failed("task event sequence exhausted".into()))?,
        row,
    };
    let key = task_key(at.caller, &next.row.task_id);
    let mut writes = vec![
        Write {
            kind: KIND_TASK,
            key: key.clone(),
            value: encode(&next)?,
        },
        Write {
            kind: KIND_TASK_EVENT,
            key: key.clone(),
            value: suffix(&ev),
        },
    ];
    let mut predicates = vec![Predicate {
        kind: KIND_TASK,
        key: key.clone(),
        expected: expected.map(crate::relay::RawBytes::into_vec),
    }];
    if let Some((expected, value)) = config.take() {
        predicates.push(Predicate {
            kind: KIND_PUSH_CONFIG,
            key: key.clone(),
            expected,
        });
        writes.push(Write {
            kind: KIND_PUSH_CONFIG,
            key,
            value,
        });
    }
    let applied = rec.publish(&predicates, &[chain], &writes)?;
    Ok(applied.then_some(next))
}

/// The genesis commit of a task, answering it as held.
#[cfg(test)]
fn submit_held(
    rec: &mut dyn Records,
    at: &Stamp<'_>,
    genesis: &HeldTask,
    row: TaskRow,
    _out: &mut Vec<Write>,
) -> Result<HeldTask, Halt> {
    let id = row.task_id.clone();
    let key = task_key(at.caller, &id);
    let chain = observe(rec, &key)?;
    if rec.get(KIND_TASK, &key)?.is_some() {
        return Err(Halt::Failed(format!("task `{id}` already exists")));
    }
    commit(rec, at, genesis, (None, chain), row, EV_SUBMITTED, None)?
        .ok_or_else(|| Halt::Failed(format!("task `{id}` already exists")))
}

/// Open a relayed task with one atomic publication: the final row and the submitted/delegated
#[cfg(test)]
pub fn open(
    rec: &mut dyn Records,
    at: &Stamp<'_>,
    row: TaskRow,
    agent_id: &str,
    _out: &mut Vec<Write>,
) -> Result<TaskRow, Halt> {
    open_configured(rec, at, row, agent_id, None)
}

/// Open a task and its optional inline config in the same publication as both genesis events.
pub(crate) fn open_configured(
    rec: &mut dyn Records,
    at: &Stamp<'_>,
    mut row: TaskRow,
    agent_id: &str,
    config: Option<Vec<u8>>,
) -> Result<TaskRow, Halt> {
    let config = config.map(crate::relay::RawBytes::from);
    if !is_caller(at.caller) {
        return Err(Halt::Failed("no caller to hold the task under".into()));
    }
    row.principal = at.caller.to_string();
    let key = task_key(at.caller, &row.task_id);
    let chain = observe(rec, &key)?;
    if rec.get(KIND_TASK, &key)?.is_some() {
        return Err(Halt::Failed(format!(
            "task `{}` already exists",
            row.task_id
        )));
    }
    let genesis = HeldTask {
        row: row.clone(),
        next_seq: 1,
    };
    let stamped = Stamp {
        now: row.created_at,
        ..*at
    };
    let submitted = seal_event(&genesis, &row, EV_SUBMITTED, at.request_id, stamped.now);
    let held = HeldTask {
        row: row.clone(),
        next_seq: 2,
    };
    let mut next = row;
    next.agent_id = agent_id.to_string();
    next.updated_at = at.now;
    let delegated = seal_event(&held, &next, EV_DELEGATED, at.request_id, at.now);
    let next = HeldTask {
        row: next,
        next_seq: 3,
    };
    let key = task_key(at.caller, &next.row.task_id);
    let mut writes = vec![
        Write {
            kind: KIND_TASK,
            key: key.clone(),
            value: encode(&next)?,
        },
        Write {
            kind: KIND_TASK_EVENT,
            key: key.clone(),
            value: suffix(&submitted),
        },
        Write {
            kind: KIND_TASK_EVENT,
            key: key.clone(),
            value: suffix(&delegated),
        },
    ];
    let mut predicates = vec![Predicate {
        kind: KIND_TASK,
        key: key.clone(),
        expected: None,
    }];
    if let Some(value) = config {
        let expected = rec.get(KIND_PUSH_CONFIG, &key)?;
        predicates.push(Predicate {
            kind: KIND_PUSH_CONFIG,
            key: key.clone(),
            expected,
        });
        writes.push(Write {
            kind: KIND_PUSH_CONFIG,
            key,
            value: value.into_vec(),
        });
    }
    if rec.publish(&predicates, &[chain], &writes)? {
        Ok(next.row)
    } else {
        Err(Halt::Failed(format!(
            "task `{}` already exists",
            next.row.task_id
        )))
    }
}

/// What a change does to one held row: the new row and its event, `None` for nothing to do, or the
pub type Planned = Result<Option<(TaskRow, &'static str)>, String>;

/// A change's plan over the held row.
pub type Plan<'p> = dyn FnMut(&TaskRow) -> Planned + 'p;

/// Change task `task` by `plan`: read exact bytes, plan and atomically compare/publish.
pub fn change(
    rec: &mut dyn Records,
    at: &Stamp<'_>,
    task: &str,
    plan: &mut Plan<'_>,
    _out: &mut Vec<Write>,
) -> Result<Option<TaskRow>, Halt> {
    change_configured(rec, at, task, plan, None)
}

/// Change a task and replace an optional inline config in one atomic publication.
pub(crate) fn change_configured(
    rec: &mut dyn Records,
    at: &Stamp<'_>,
    task: &str,
    plan: &mut Plan<'_>,
    config: Option<&[u8]>,
) -> Result<Option<TaskRow>, Halt> {
    for _ in 0..TRIES {
        if !is_caller(at.caller) {
            return Err(Halt::Failed(format!("no such task `{task}`")));
        }
        let chain = observe(rec, &task_key(at.caller, task))?;
        let raw = rec.get(KIND_TASK, &task_key(at.caller, task))?;
        let Some(held) = raw
            .as_deref()
            .and_then(decode)
            .filter(|h| !expired(&h.row, at.now))
        else {
            return Err(Halt::Failed(format!("no such task `{task}`")));
        };
        let Some((row, kind)) = plan(&held.row).map_err(Halt::Failed)? else {
            return Ok(None);
        };
        if row.task_id != task || row.principal != held.row.principal {
            return Err(Halt::Failed(
                "a task change cannot change its identity".into(),
            ));
        }
        let config = config
            .map(|value| {
                rec.get(KIND_PUSH_CONFIG, &task_key(at.caller, task))
                    .map(|expected| (expected, value.to_vec()))
            })
            .transpose()?;
        if commit(rec, at, &held, (raw, chain), row.clone(), kind, config)?.is_some() {
            return Ok(Some(row));
        }
    }
    Err(Halt::Failed(format!(
        "task `{task}` kept changing under this write"
    )))
}

/// TRANSITION task `task` to `to`, with the event the move names.
pub fn transition(
    rec: &mut dyn Records,
    at: &Stamp<'_>,
    task: &str,
    to: TaskState,
    out: &mut Vec<Write>,
) -> Result<Option<TaskRow>, Halt> {
    let mut plan = |row: &TaskRow| -> Planned { plan_transition(to, at.now)(row).map(Some) };
    change(rec, at, task, &mut plan, out)
}

/// ADVANCE the artifact cursor by one chunk, with a `task.artifact` event, per
pub fn bump_cursor(
    rec: &mut dyn Records,
    at: &Stamp<'_>,
    task: &str,
    out: &mut Vec<Write>,
) -> Result<Option<TaskRow>, Halt> {
    let mut plan = |row: &TaskRow| -> Planned {
        let mut next = row.clone();
        next.artifact_cursor = row.artifact_cursor.saturating_add(1);
        next.updated_at = at.now;
        Ok(Some((next, EV_ARTIFACT)))
    };
    change(rec, at, task, &mut plan, out)
}

/// RECORD one push delivery outcome `kind` on the task's chain; the row itself is unchanged.
pub fn record_push_delivery(
    rec: &mut dyn Records,
    at: &Stamp<'_>,
    task: &str,
    kind: &'static str,
    out: &mut Vec<Write>,
) -> Result<(), Halt> {
    let mut plan = |row: &TaskRow| -> Planned { Ok(Some((row.clone(), kind))) };
    change(rec, at, task, &mut plan, out).map(|_| ())
}

/// THE RETENTION SWEEP at `now`, the plane's own purge of the task kind under its rule
pub fn retention_sweep(
    rec: &mut dyn Records,
    now: u64,
    budget: usize,
    _out: &mut Vec<Write>,
) -> Result<usize, Halt> {
    let rule = retention_of(KIND_TASK);
    let mut held: Vec<(String, HeldTask, Vec<u8>)> = rec
        .list(KIND_TASK, "")?
        .into_iter()
        .filter_map(|(key, bytes)| {
            let held = decode(&bytes)?;
            let (caller, _) = key.split_once('/')?;
            (is_caller(caller) && key == task_key(caller, &held.row.task_id))
                .then_some((key, held, bytes))
        })
        .filter(|(_, held, _)| rule.reaches(terminal(&held.row.state)))
        .collect();
    held.sort_by(|a, b| {
        (a.1.row.updated_at, &a.1.row.task_id).cmp(&(b.1.row.updated_at, &b.1.row.task_id))
    });
    let mut touched = 0usize;
    let mut kept = held.len();
    for (key, candidate, expected) in &held {
        let row = &candidate.row;
        if touched < budget && (kept >= MAX_RETAINED || expired(row, now)) {
            let chain = observe(rec, key)?;

            let current = rec.get(KIND_TASK, key)?;
            if current.as_ref() != Some(expected) || !forget(rec, key, expected, chain)? {
                continue;
            }
            kept -= 1;
            touched += 1;
        }
    }
    Ok(touched)
}

/// Tombstone `caller`'s task `task`, its push config, and its events (the chain dropped whole).
fn forget(
    rec: &mut dyn Records,
    key: &str,
    expected: &[u8],
    chain: ChainLife,
) -> Result<bool, Halt> {
    let writes = [KIND_TASK_EVENT, KIND_TASK, KIND_PUSH_CONFIG].map(|kind| Write {
        kind,
        key: key.to_string(),
        value: Vec::new(),
    });
    rec.publish(
        &[Predicate {
            kind: KIND_TASK,
            key: key.to_string(),
            expected: Some(expected.to_vec()),
        }],
        &[chain],
        &writes,
    )
}

/// Atomically replace or delete a config only while its task still has the exact observed row.
pub(crate) fn write_config(
    rec: &mut dyn Records,
    at: &Stamp<'_>,
    task: &str,
    expected: Option<Vec<u8>>,
    value: Vec<u8>,
) -> Result<bool, Halt> {
    let expected = expected.map(crate::relay::RawBytes::from);
    let value = crate::relay::RawBytes::from(value);
    if !is_caller(at.caller) {
        return Err(Halt::Failed("no caller to hold the task under".into()));
    }
    let key = task_key(at.caller, task);
    let chain = observe(rec, &key)?;
    let raw = rec.get(KIND_TASK, &key)?;
    if raw
        .as_deref()
        .and_then(decode)
        .filter(|held| !expired(&held.row, at.now))
        .is_none()
    {
        return Err(Halt::Failed(format!("no such task `{task}`")));
    }
    rec.publish(
        &[
            Predicate {
                kind: KIND_TASK,
                key: key.clone(),
                expected: raw,
            },
            Predicate {
                kind: KIND_PUSH_CONFIG,
                key: key.clone(),
                expected: expected.map(crate::relay::RawBytes::into_vec),
            },
        ],
        &[chain],
        &[Write {
            kind: KIND_PUSH_CONFIG,
            key,
            value: value.into_vec(),
        }],
    )
}

/// The existing bounded conflict retry policy for task and config writers.
pub(crate) const fn attempts() -> std::ops::Range<usize> {
    0..TRIES
}

#[cfg(test)]
#[path = "tests/tasks.rs"]
pub(crate) mod tests;

#[cfg(test)]
#[path = "tests/record_raw_custody.rs"]
mod raw_custody_tests;
