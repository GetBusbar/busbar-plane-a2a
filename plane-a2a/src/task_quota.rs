// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Durable active-task admission, in the same conditional transaction as each task change.
//!
//! Initializing a fresh store requires the host's instance/store-bound cold bootstrap receipt.
//! Unsupported or unattested hosts refuse initialization. Reloading a generation is not that
//! barrier. Existing task-owned records or principal quota metadata without a ready gate are
//! inconsistent state, never input to a quota reconstruction. An interrupted empty-store
//! initialization may resume under the same durable gate; ready current-format stores restart
//! directly from their persisted quota state.

use serde::{Deserialize, Serialize};

use crate::records::{KIND_PUSH_CONFIG, KIND_TASK, KIND_TASK_EVENT, KIND_TASK_QUOTA};
use crate::tasks::{ChainLife, Halt, HeldTask, Predicate, Records, Write};

/// The fixed active-task bound, for both one instance and one principal.
pub(crate) const MAX_ACTIVE: u64 = 4096;
/// Public-safe refusal words for exhausted durable active-task capacity.
pub(crate) const CAPACITY_REFUSAL: &str = "active task capacity reached";
const GLOBAL: &str = "active/v1";
const VERSION: u8 = 1;
const EPOCH: u64 = 1;

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

/// Initialization never reconstructs quota from task-owned state, even terminal rows. If a
/// concurrent initializer has advanced the gate, retry instead of mistaking its valid rows for
/// corruption. A listing failure is never evidence of emptiness.
fn initialization_empty(rec: &mut dyn Records, expected: Option<&[u8]>) -> Result<bool, Halt> {
    for kind in [
        KIND_TASK_QUOTA,
        KIND_TASK,
        KIND_TASK_EVENT,
        KIND_PUSH_CONFIG,
    ] {
        let listed = crate::proto::custody::Guard::new(rec.list(kind, "")?);
        let populated = listed
            .iter()
            .any(|(key, _)| kind != KIND_TASK_QUOTA || expected.is_none() || key != GLOBAL);
        if populated {
            if rec.get(KIND_TASK_QUOTA, GLOBAL)?.as_deref() != expected {
                return Ok(false);
            }
            return Err(failed());
        }
    }
    Ok(true)
}

/// Finish only an empty initialization, guarded by the exact durable initializing bytes.
fn bootstrap(rec: &mut dyn Records, gate: &Gate, bytes: &[u8]) -> Result<bool, Halt> {
    if !initialization_empty(rec, Some(bytes))? {
        return Ok(false);
    }
    rec.publish(
        &[gate_predicate(bytes)],
        &[],
        &[Write {
            kind: KIND_TASK_QUOTA,
            key: GLOBAL.into(),
            value: encode(&Gate {
                active: Some(0),
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
            if !initialization_empty(rec, None)? {
                continue;
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
    let mut mixed_reads = crate::tasks::attempts();
    loop {
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
                let _ = mixed_reads.next();
                if mixed_reads.is_empty() {
                    return Ok(false);
                }
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
            // An active-to-active or terminal-to-terminal update does not change either
            // counter. Keep the validated predicates, but avoid writing identical quota rows.
            if before != after {
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
        }
        if rec.publish(&guarded, chains, &mutations)? {
            return Ok(true);
        }
        // A shared quota conflict is not a change to this task. Recheck the entire original
        // plan before spending another quota attempt; a task/config/life change still belongs
        // to the task planner. Every retry retains all predicates in the atomic transaction.
        for predicate in predicates {
            let current = rec
                .get(predicate.kind, &predicate.key)?
                .map(crate::relay::RawBytes::from);
            if current.as_deref() != predicate.expected.as_deref() {
                return Ok(false);
            }
        }
        for chain in chains {
            if rec.observe_chain_life(chain.kind, &chain.scope)? != chain.expected {
                return Ok(false);
            }
        }
        if !rec.retry_quota()? {
            return Ok(false);
        }
    }
}
