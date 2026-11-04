// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Raw callback fixture host: atomic logical mutations and exact operation replay. This models
//! //! the bridge exchange and its store decision, not chain sealing or a real backend.

use super::*;
use busbar_contract::abi::sdk::plane::conditional as wire;
use busbar_contract::abi::sdk::store::conditional::{Decision, Expected};
use std::collections::HashMap;

type Owner = (u32, u32);
type Call = (u64, u32);

#[derive(Clone)]
enum Intent {
    Observe(wire::Observation),
    Publish(wire::Request),
}

#[derive(Default)]
struct Cycle {
    epoch: u64,
    unfinished: bool,
    pending: Option<Intent>,
    receipt: Vec<u8>,
}

#[derive(Default)]
pub(super) struct Host {
    cycles: HashMap<Owner, Cycle>,
    next_epoch: u64,
    next_life: u64,
    lives: HashMap<(u32, Vec<u8>), Vec<u8>>,
    gets: HashMap<Call, Option<Vec<u8>>>,
    lists: HashMap<Call, Vec<(String, Vec<u8>)>>,
    random: HashMap<Call, u8>,
    decisions: HashMap<(u64, u64), Vec<u8>>,
    detached: Option<(wire::Request, Vec<u8>)>,
    pub(super) acknowledgements: usize,
    pub(super) requests: Vec<wire::Request>,
    pub(super) emitted: Vec<wire::Request>,
    pub(super) observations: Vec<wire::Observation>,
    pub(super) reads: Vec<(u64, u32, String, String)>,
    pub(super) applied: usize,
    pub(super) events: Vec<(Vec<u8>, Vec<u8>)>,
    pub(super) pause_commit: bool,
    pub(super) pause_owed_commit: bool,
    pub(super) conflict_once: bool,
    pub(super) lose_applied_once: bool,
}

fn owner(t: Ticket) -> Owner {
    (t.slot, t.generation)
}
fn name(kind: u32) -> String {
    door_facts::HELD_KINDS[kind as usize].to_string()
}
fn bytes_key(key: &[u8]) -> String {
    String::from_utf8(key.to_vec()).unwrap()
}

impl Host {
    /// Finish the already copied original attempt without invoking the canceled guest again.
    pub(super) fn detach(&mut self, ticket: Ticket) -> Vec<u8> {
        self.pause_commit = false;
        self.pause_owed_commit = false;
        self.complete(ticket, false);
        let request = self
            .emitted
            .iter()
            .rev()
            .find(|r| r.capability.ticket == ticket)
            .unwrap()
            .clone();
        let result = wire::read_result(
            &self.decisions[&(request.capability.epoch, request.candidate.correlation)],
            &request,
        )
        .unwrap()
        .unwrap();
        let receipt = wire::encode_settlement(&request, &result).unwrap();
        self.detached = Some((request, receipt.clone()));
        receipt
    }

    pub(super) fn retained_settlement(&self) -> Option<Vec<u8>> {
        self.detached.as_ref().map(|(_, receipt)| receipt.clone())
    }

    /// The host consumes only the exact receipt's ACK on a successful, complete driver answer.
    pub(super) fn acknowledge(&mut self, extensions: &[u8], outcome: Outcome, short: bool) -> bool {
        let Some(ack) = wire::read_settlement_ack(extensions).unwrap() else {
            return false;
        };
        let Some((request, _)) = &self.detached else {
            return false;
        };
        if outcome != Outcome::Pending || short || !ack.matches(request).unwrap() {
            return false;
        }
        self.detached = None;
        self.acknowledgements += 1;
        true
    }

    pub(super) fn begin(&mut self, ticket: Ticket, resuming: bool, refused: bool) -> Vec<u8> {
        let key = owner(ticket);
        let continuing = self.cycles.get(&key).is_some_and(|c| c.unfinished) || resuming;
        if !continuing || !self.cycles.contains_key(&key) {
            self.next_epoch = self.next_epoch.checked_add(1).unwrap();
            self.cycles.insert(
                key,
                Cycle {
                    epoch: self.next_epoch,
                    unfinished: true,
                    ..Cycle::default()
                },
            );
        }
        self.complete(ticket, refused);
        self.input(ticket)
    }

    fn input(&self, ticket: Ticket) -> Vec<u8> {
        let cycle = &self.cycles[&owner(ticket)];
        let mut input = wire::encode_capability(wire::Capability {
            ticket,
            epoch: cycle.epoch,
        });
        input.extend_from_slice(&cycle.receipt);
        input
    }

    pub(super) fn returned(
        &mut self,
        ticket: Ticket,
        outcome: Outcome,
        short: bool,
        extensions: &[u8],
        refused: bool,
    ) -> Option<Vec<u8>> {
        let observed = wire::read_observation(extensions).unwrap();
        let published = wire::read_request(extensions).unwrap();
        assert!(!(observed.is_some() && published.is_some()));
        let intent = observed
            .map(Intent::Observe)
            .or_else(|| published.map(Intent::Publish));
        if let Some(intent) = intent {
            assert_eq!(
                outcome,
                Outcome::Pending,
                "intent is only published PENDING"
            );
            if let Intent::Publish(request) = &intent {
                self.emitted.push(request.clone());
            }
            let c = self.cycles.get_mut(&owner(ticket)).unwrap();
            c.pending = Some(intent);
            c.receipt.clear();
            c.unfinished = true;
            if self.complete(ticket, refused) {
                Some(self.input(ticket))
            } else {
                None
            }
        } else {
            self.cycles.get_mut(&owner(ticket)).unwrap().unfinished =
                outcome == Outcome::Pending || short;
            None
        }
    }

    fn complete(&mut self, ticket: Ticket, refused: bool) -> bool {
        let key = owner(ticket);
        let Some(intent) = self.cycles[&key].pending.clone() else {
            return false;
        };
        let (epoch, correlation) = match &intent {
            Intent::Observe(r) => (r.capability.epoch, r.correlation),
            Intent::Publish(r) => (r.capability.epoch, r.candidate.correlation),
        };
        if let Some(receipt) = self.decisions.get(&(epoch, correlation)).cloned() {
            let cycle = self.cycles.get_mut(&key).unwrap();
            cycle.receipt = receipt;
            cycle.pending = None;
            return true;
        }
        if matches!(&intent, Intent::Publish(request) if self.pause_commit ||
            (self.pause_owed_commit && request.candidate.chains.iter().any(|chain|
                matches!(chain, wire::ChainMutation::Append { kind, content, .. }
                    if door_facts::HELD_KINDS.get(*kind as usize) == Some(&"task_event")
                        && task_event_kind(content) == "task.push_delivered"))))
        {
            return false;
        }
        let receipt = match intent {
            Intent::Observe(request) => {
                self.observations.push(request.clone());
                let life = self
                    .lives
                    .get(&(request.kind, request.scope.clone()))
                    .cloned()
                    .map_or(Expected::Absent, Expected::Bytes);
                wire::encode_observed(
                    &request,
                    &wire::ObservationResult {
                        correlation,
                        result: Ok(life),
                    },
                )
                .unwrap()
            }
            Intent::Publish(request) => {
                self.requests.push(request.clone());
                let decision = if refused {
                    Err(wire::ConditionalFailure::Refused("fixture store refusal"))
                } else {
                    if std::mem::take(&mut self.conflict_once) {
                        let p = request
                            .candidate
                            .predicates
                            .iter()
                            .find(|p| p.kind == 0)
                            .unwrap();
                        let mut rows = store();
                        let row = rows
                            .iter_mut()
                            .find(|(kind, key, _)| kind == "task" && *key == bytes_key(&p.key))
                            .unwrap();
                        let mut doc: Value = serde_json::from_slice(&row.2).unwrap();
                        doc["artifact_cursor"] =
                            json!(doc["artifact_cursor"].as_u64().unwrap() + 1);
                        row.2 = serde_json::to_vec(&doc).unwrap();
                    }
                    Ok(self.apply(&request))
                };
                let receipt = wire::encode_result(
                    &request,
                    &wire::ConditionalResult {
                        correlation,
                        decision: decision.clone(),
                    },
                )
                .unwrap();
                if decision == Ok(Decision::Applied) && std::mem::take(&mut self.lose_applied_once)
                {
                    self.decisions.insert((epoch, correlation), receipt);

                    self.cycles.get_mut(&key).unwrap().receipt.clear();
                    return true;
                }
                receipt
            }
        };
        self.decisions.insert((epoch, correlation), receipt.clone());
        let cycle = self.cycles.get_mut(&key).unwrap();
        cycle.receipt = receipt;
        cycle.pending = None;
        true
    }

    fn apply(&mut self, request: &wire::Request) -> Decision {
        let c = &request.candidate;
        let mut rows = store();
        for p in &c.predicates {
            let actual = rows
                .iter()
                .find(|(k, key, _)| *k == name(p.kind) && *key == bytes_key(&p.key))
                .map(|(_, _, v)| v.clone());
            if actual.map_or(Expected::Absent, Expected::Bytes) != p.expected {
                return Decision::ConditionConflict;
            }
        }
        for chain in &c.chains {
            let (kind, scope, life) = match chain {
                wire::ChainMutation::Check { kind, scope, life }
                | wire::ChainMutation::Append {
                    kind, scope, life, ..
                }
                | wire::ChainMutation::Drop { kind, scope, life } => (*kind, scope, life),
            };
            let actual = self
                .lives
                .get(&(kind, scope.clone()))
                .cloned()
                .map_or(Expected::Absent, Expected::Bytes);
            if &actual != life {
                return Decision::ConditionConflict;
            }
        }
        for mutation in &c.mutations {
            let (kind, key, value) = match mutation {
                wire::RecordMutation::Put { kind, key, value } => (*kind, key, Some(value.clone())),
                wire::RecordMutation::Delete { kind, key } => (*kind, key, None),
            };
            let name = name(kind);
            let key = bytes_key(key);
            rows.retain(|(k, id, _)| *k != name || *id != key);
            if let Some(value) = value {
                rows.push((name, key, value));
            }
        }
        for chain in &c.chains {
            match chain {
                wire::ChainMutation::Check { .. } => {}
                wire::ChainMutation::Append {
                    kind,
                    scope,
                    content,
                    ..
                } => {
                    if !self.lives.contains_key(&(*kind, scope.clone())) {
                        self.next_life = self.next_life.checked_add(1).unwrap();
                        self.lives.insert(
                            (*kind, scope.clone()),
                            self.next_life.to_le_bytes().to_vec(),
                        );
                    }
                    self.events.push((scope.clone(), content.clone()));
                }
                wire::ChainMutation::Drop { kind, scope, .. } => {
                    self.next_life = self.next_life.checked_add(1).unwrap();
                    self.lives.insert(
                        (*kind, scope.clone()),
                        self.next_life.to_le_bytes().to_vec(),
                    );
                    self.events.retain(|(s, _)| s != scope);
                    let name = name(*kind);
                    let key = bytes_key(scope);
                    rows.retain(|(k, id, _)| {
                        *k != name || (*id != key && !id.starts_with(&format!("{key}/")))
                    });
                }
            }
        }
        self.applied += 1;
        Decision::Applied
    }

    fn call(&self, head: ServiceHead) -> Option<Call> {
        self.cycles
            .get(&owner(head.handle.ticket))
            .filter(|c| c.unfinished)
            .map(|c| (c.epoch, head.handle.seq))
    }

    pub(super) fn get(&mut self, head: ServiceHead, kind: &str, key: &str) -> Option<Vec<u8>> {
        let Some(call) = self.call(head) else {
            return store()
                .iter()
                .find(|(k, id, _)| k == kind && id == key)
                .map(|(_, _, v)| v.clone());
        };
        if !self.gets.contains_key(&call) {
            self.reads.push((call.0, call.1, kind.into(), key.into()));
        }
        self.gets
            .entry(call)
            .or_insert_with(|| {
                store()
                    .iter()
                    .find(|(k, id, _)| k == kind && id == key)
                    .map(|(_, _, v)| v.clone())
            })
            .clone()
    }

    pub(super) fn list(
        &mut self,
        head: ServiceHead,
        kind: &str,
        prefix: &str,
        after: &str,
        limit: usize,
    ) -> (bool, Vec<(String, Vec<u8>)>) {
        let read = || {
            let mut rows: Vec<_> = store()
                .iter()
                .filter(|(k, key, _)| {
                    k == kind
                        && key.starts_with(prefix)
                        && (after.is_empty() || key.as_str() > after)
                })
                .map(|(_, k, v)| (k.clone(), v.clone()))
                .collect();
            rows.sort();
            rows.truncate(limit);
            rows
        };
        let Some(call) = self.call(head) else {
            return (true, read());
        };
        let fresh = !self.lists.contains_key(&call);
        let rows = self.lists.entry(call).or_insert_with(read).clone();
        (fresh, rows)
    }

    pub(super) fn random(&mut self, head: ServiceHead, next: u8) -> u8 {
        let Some(call) = self.call(head) else {
            return next;
        };
        *self.random.entry(call).or_insert(next)
    }
}
