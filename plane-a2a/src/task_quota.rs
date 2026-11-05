// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Durable active-task admission, in the same conditional transaction as each task change.
//!
//! A pre-quota store requires a cold upgrade: stop every old writer and settle its admitted
//! transactions before starting this build, then provide the host's instance/store-bound cold
//! bootstrap receipt. An unsupported or unattested host refuses bootstrap at runtime. Reloading
//! a generation is not that barrier. During
//! bootstrap every writer predicates the initializing gate; no task changes until the complete
//! snapshot's counters are published. An interrupted bootstrap may be repeated by another caller.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::records::{KIND_PUSH_CONFIG, KIND_TASK, KIND_TASK_QUOTA};
use crate::tasks::{ChainLife, Halt, HeldTask, Predicate, Records, Write};

/// The fixed active-task bound, for both one instance and one principal.
pub(crate) const MAX_ACTIVE: u64 = 4096;
/// Public-safe refusal words for exhausted durable active-task capacity.
pub(crate) const CAPACITY_REFUSAL: &str = "active task capacity reached";
const GLOBAL: &str = "active/v1";
const VERSION: u8 = 1;
const EPOCH: u64 = 1;
const BOOTSTRAP_BATCH: usize = 16;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Gate {
    version: u8,
    epoch: u64,
    // None is the durable writer barrier. Some is the complete active count.
    active: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Count {
    version: u8,
    epoch: u64,
    active: u64,
}

fn failed() -> Halt {
    Halt::Failed("active task quota is unavailable or inconsistent".into())
}

fn encode(value: &impl Serialize) -> Result<Vec<u8>, Halt> {
    let bytes = serde_json::to_vec(value).map_err(|_| failed())?;
    if bytes.len() > busbar_contract::bounded::MAX_RECORD_BYTES {
        return Err(failed());
    }
    Ok(bytes)
}

fn principal_key(epoch: u64, principal: &str) -> String {
    format!("{epoch}/{principal}")
}

fn task(bytes: &[u8], key: &str) -> Result<HeldTask, Halt> {
    let held: HeldTask = crate::request_json::from_slice(bytes).map_err(|_| failed())?;
    crate::a2a::task::readable_row(&held.row).map_err(|_| failed())?;
    if !crate::tasks::is_caller(&held.row.principal)
        || crate::tasks::task_key(&held.row.principal, &held.row.task_id) != key
        || held.next_seq == 0
    {
        return Err(failed());
    }
    Ok(held)
}

fn active(held: &HeldTask) -> bool {
    // task() has already validated this closed-domain token.
    !crate::a2a::task::TaskState::parse(&held.row.state)
        .expect("validated task state")
        .is_terminal()
}

fn gate_predicate(bytes: &[u8]) -> Predicate {
    Predicate {
        kind: KIND_TASK_QUOTA,
        key: GLOBAL.into(),
        expected: Some(bytes.to_vec()),
    }
}

/// Reconstruct only while all task writers are fenced by the exact durable initializing bytes.
/// Records::list must return every row or an error. The host's listing limits are errors, never
/// permission to activate a partial count; larger legacy stores require an offline migration.
fn bootstrap(rec: &mut dyn Records, gate: &Gate, bytes: &[u8]) -> Result<bool, Halt> {
    let listed = crate::proto::custody::Guard::new(rec.list(KIND_TASK, "")?);
    let mut counts = BTreeMap::<String, u64>::new();
    let mut total = 0u64;
    for (key, bytes) in listed.iter() {
        let held = task(bytes, key)?;
        if active(&held) {
            total = total.checked_add(1).ok_or_else(failed)?;
            let count = counts.entry(held.row.principal.clone()).or_default();
            *count = count.checked_add(1).ok_or_else(failed)?;
        }
    }
    let counts: Vec<_> = counts.into_iter().collect();
    for batch in counts.chunks(BOOTSTRAP_BATCH) {
        let writes = batch
            .iter()
            .map(|(principal, count)| {
                Ok(Write {
                    kind: KIND_TASK_QUOTA,
                    key: principal_key(gate.epoch, principal),
                    value: encode(&Count {
                        version: VERSION,
                        epoch: gate.epoch,
                        active: *count,
                    })?,
                })
            })
            .collect::<Result<Vec<_>, Halt>>()?;
        if !rec.publish(&[gate_predicate(bytes)], &[], &writes)? {
            return Ok(false);
        }
    }
    rec.publish(
        &[gate_predicate(bytes)],
        &[],
        &[Write {
            kind: KIND_TASK_QUOTA,
            key: GLOBAL.into(),
            value: encode(&Gate {
                active: Some(total),
                ..gate.clone()
            })?,
        }],
    )
}

fn ready(rec: &mut dyn Records) -> Result<(Gate, Vec<u8>), Halt> {
    for _ in crate::tasks::attempts() {
        let raw = rec.get(KIND_TASK_QUOTA, GLOBAL)?;
        let (gate, bytes) = if let Some(bytes) = raw {
            let gate: Gate = crate::request_json::from_slice(&bytes).map_err(|_| failed())?;
            if gate.version != VERSION || gate.epoch != EPOCH {
                return Err(failed());
            }
            if gate.active.is_some() {
                return Ok((gate, bytes));
            }
            if !rec.quota_bootstrap_allowed()? {
                return Err(failed());
            }
            (gate, bytes)
        } else {
            if !rec.quota_bootstrap_allowed()? {
                return Err(failed());
            }
            // Missing global metadata beside existing quota records is corruption, not a fresh
            // store. Do not let missing metadata silently reset previously charged capacity.
            if !rec.list(KIND_TASK_QUOTA, "")?.is_empty() {
                return Err(failed());
            }
            let gate = Gate {
                version: VERSION,
                epoch: EPOCH,
                active: None,
            };
            let bytes = encode(&gate)?;
            if !rec.publish(
                &[Predicate {
                    kind: KIND_TASK_QUOTA,
                    key: GLOBAL.into(),
                    expected: None,
                }],
                &[],
                &[Write {
                    kind: KIND_TASK_QUOTA,
                    key: GLOBAL.into(),
                    value: bytes.clone(),
                }],
            )? {
                continue;
            }
            (gate, bytes)
        };
        if bootstrap(rec, &gate, &bytes)? {
            // Read again on a fresh replay handle: another admitted transaction may already
            // have changed the ready count after the activation receipt.
            continue;
        }
    }
    Err(failed())
}

/// Publish a task/config change with its durable admission or release. Replay retains every
/// metadata read and exact transaction through the existing Records implementation.
pub(crate) fn publish(
    rec: &mut dyn Records,
    predicates: &[Predicate],
    chains: &[ChainLife],
    writes: &[Write],
) -> Result<bool, Halt> {
    let mut changed = writes.iter().filter(|write| write.kind == KIND_TASK);
    let row = changed.next();
    if changed.next().is_some() {
        return Err(failed());
    }
    if row.is_none() && !writes.iter().any(|write| write.kind == KIND_PUSH_CONFIG) {
        return Err(failed());
    }
    let mutation = row
        .map(|write| -> Result<_, Halt> {
            let mut observed = predicates
                .iter()
                .filter(|p| p.kind == KIND_TASK && p.key == write.key);
            let observed = observed.next().ok_or_else(failed)?;
            let before = observed
                .expected
                .as_deref()
                .map(|bytes| task(bytes, &write.key))
                .transpose()?;
            let after = (!write.value.is_empty())
                .then(|| task(&write.value, &write.key))
                .transpose()?;
            let principal = after
                .as_ref()
                .or(before.as_ref())
                .ok_or_else(failed)?
                .row
                .principal
                .clone();
            if before
                .as_ref()
                .is_some_and(|held| held.row.principal != principal)
            {
                return Err(failed());
            }
            Ok((
                principal,
                before.as_ref().is_some_and(active),
                after.as_ref().is_some_and(active),
            ))
        })
        .transpose()?;
    for _ in crate::tasks::attempts() {
        let (gate, gate_bytes) = ready(rec)?;
        let total = gate.active.ok_or_else(failed)?;
        let mut guarded = predicates.to_vec();
        let mut mutations = writes.to_vec();
        guarded.push(gate_predicate(&gate_bytes));
        if let Some((principal, before, after)) = &mutation {
            let key = principal_key(gate.epoch, principal);
            let raw = rec.get(KIND_TASK_QUOTA, &key)?;
            let count = match raw.as_deref() {
                Some(bytes) => {
                    let count: Count =
                        crate::request_json::from_slice(bytes).map_err(|_| failed())?;
                    if count.version != VERSION || count.epoch != gate.epoch {
                        return Err(failed());
                    }
                    count.active
                }
                None => 0,
            };
            if count > total || (*before && (count == 0 || total == 0)) {
                // These independent reads may straddle another valid publication. Never call
                // that corruption or release from a mixed snapshot. A persistent mismatch
                // fails closed as a conflict, letting the caller replan its task as well.
                continue;
            }
            let adjust = |value: u64| {
                value
                    .checked_sub(u64::from(*before))
                    .and_then(|value| value.checked_add(u64::from(*after)))
                    .ok_or_else(failed)
            };
            let next_total = adjust(total)?;
            let next_count = adjust(count)?;
            if !*before && *after && (next_total > MAX_ACTIVE || next_count > MAX_ACTIVE) {
                return Err(Halt::Failed(CAPACITY_REFUSAL.into()));
            }
            guarded.push(Predicate {
                kind: KIND_TASK_QUOTA,
                key: key.clone(),
                expected: raw,
            });
            mutations.push(Write {
                kind: KIND_TASK_QUOTA,
                key,
                value: if next_count == 0 {
                    Vec::new()
                } else {
                    encode(&Count {
                        version: VERSION,
                        epoch: gate.epoch,
                        active: next_count,
                    })?
                },
            });
            mutations.push(Write {
                kind: KIND_TASK_QUOTA,
                key: GLOBAL.into(),
                value: encode(&Gate {
                    active: Some(next_total),
                    ..gate
                })?,
            });
        }
        // A definitive conflict belongs to the task planner. Retrying this exact task
        // predicate here would keep replaying stale row bytes instead of rereading the row.
        return rec.publish(&guarded, chains, &mutations);
    }
    Ok(false)
}
