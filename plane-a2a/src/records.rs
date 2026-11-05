// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The plane's durable state: the HOST record kinds it keeps, by name.

/// The `task` kind — the durable task record's tag on the store seam.
pub const KIND_TASK: &str = "task";

/// The `task_event` kind — the durable task-event record's tag on the store seam.
pub const KIND_TASK_EVENT: &str = "task_event";

/// The `push_config` kind — a task's push-notification config, held as a host record.
pub const KIND_PUSH_CONFIG: &str = "push_config";

/// The `card` kind — an agent's verified card, keyed by agent id under the operator's scope (no
/// principal prefix).
pub const KIND_CARD: &str = "card";

/// The `card_approval` kind — the skills (`id -> digest`) of the card the operator approved for an
/// agent, keyed like its `card` record.
pub const KIND_CARD_APPROVAL: &str = "card_approval";

/// Durable active-task quota gate and epoch-scoped principal counts; never retention-swept.
pub const KIND_TASK_QUOTA: &str = "task_quota";

/// The host-record kinds the door's tail states (`PlaneTail::record_kinds`), in order: a record
/// write names its kind by its index here.
pub const HELD_KINDS: &[&str] = &[
    KIND_TASK,
    KIND_TASK_EVENT,
    KIND_PUSH_CONFIG,
    KIND_CARD,
    KIND_CARD_APPROVAL,
    KIND_TASK_QUOTA,
];

/// WHICH rows of a held kind a retention purge may drop: every row older than the cutoff
/// ([`Retention::Age`]), or only the TERMINAL ones ([`Retention::TerminalOnly`]), an active row
/// kept however old; the tail declares the same rule per kind in `statement.rs` and the plane
/// applies it itself when it purges.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Retention {
    /// Every row older than the cutoff.
    #[default]
    Age,
    /// Only terminal rows older than the cutoff; an active row is kept regardless of age.
    TerminalOnly,
}

impl Retention {
    /// Whether a purge under this rule drops a row stamped `ts` against the cutoff `before`, given
    /// whether the row is `terminal`.
    #[must_use]
    pub const fn drops(self, ts: u64, before: u64, terminal: bool) -> bool {
        ts < before && self.reaches(terminal)
    }

    /// Whether this rule reaches a row `terminal` or not at all, whatever its age.
    #[must_use]
    pub const fn reaches(self, terminal: bool) -> bool {
        match self {
            Retention::Age => true,
            Retention::TerminalOnly => terminal,
        }
    }
}

/// The retention rule of each held kind that is not purged by age: a task row is kept while it is
/// active, so a purge drops only the terminal ones.
pub const RECORD_RETENTIONS: &[(&str, Retention)] = &[(KIND_TASK, Retention::TerminalOnly)];

/// The retention rule of held kind `kind`: its [`RECORD_RETENTIONS`] entry, [`Retention::Age`] for
/// a kind that lists none.
#[must_use]
pub fn retention_of(kind: &str) -> Retention {
    RECORD_RETENTIONS
        .iter()
        .find(|(k, _)| *k == kind)
        .map(|(_, r)| *r)
        .unwrap_or_default()
}

/// The task-event kind's index in [`HELD_KINDS`]: the kind the door declares chained.
pub const TASK_EVENT_INDEX: u32 = held_kind_index(KIND_TASK_EVENT);

/// Resolve the tail's record index from the same names used to declare its kinds.
pub const fn held_kind_index(kind: &str) -> u32 {
    let wanted = kind.as_bytes();
    let mut index = 0;
    while index < HELD_KINDS.len() {
        let candidate = HELD_KINDS[index].as_bytes();
        if candidate.len() == wanted.len() {
            let mut offset = 0;
            while offset < wanted.len() && candidate[offset] == wanted[offset] {
                offset += 1;
            }
            if offset == wanted.len() {
                return index as u32;
            }
        }
        index += 1;
    }
    u32::MAX
}
