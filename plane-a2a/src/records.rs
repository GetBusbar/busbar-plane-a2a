//! The plane's durable state: the HOST record kinds it keeps, by name.
//!
//! A plane performs no input and no output of its own. What it must remember across a restart is
//! a host record of one of the kinds below ([`HELD_KINDS`], the kinds the door's tail states): read
//! through the host's records service ([`crate::tasks::Records`]) and written as writes on the
//! unit's answer ([`crate::tasks::Write`]), never a store this crate holds. What lives only between
//! two calls is the door instance's maps, rebuilt from these records when it opens.
//!
//! | kind | what it holds |
//! |---|---|
//! | `task` | one row per task this node tracks, scoped to its caller |
//! | `task_event` | the task's hash-linked chain of state moves, the kind the door declares chained |
//! | `push_config` | a task's push-notification config, its credential a `Cred` |
//! | `card` | an agent's verified card, as `connect` recorded it |
//! | `card_approval` | the skills of the card the operator approved |
//!
//! What is not a record, because it was never this plane's to hold: a charge (the plane reports
//! units), an audit row, a breaker's verdict, an admission and an outbound credential are the
//! kernel's.

/// The `task` kind — the durable task record's tag on the store seam.
pub const KIND_TASK: &str = "task";

/// The `task_event` kind — the durable task-event record's tag on the store seam.
pub const KIND_TASK_EVENT: &str = "task_event";

/// The `push_config` kind — a task's push-notification config, held as a host record.
pub const KIND_PUSH_CONFIG: &str = "push_config";

/// The `card` kind — an agent's verified card, keyed by agent id under the operator's scope (no
/// principal prefix): the `connect` and `approve` answers write it, and the first tick after `open`
/// warms the plane's mirror of it in memory ([`crate::cards::Cards`]). A card past the host's
/// record ceiling is its parts and their head ([`crate::split_record`]), as is an approval.
pub const KIND_CARD: &str = "card";

/// The `card_approval` kind — the skills (`id -> digest`) of the card the operator approved for an
/// agent, keyed like its `card` record: the `approve` answer writes it, and the warm after `open`
/// reads it back into the trust view's standing ([`crate::card_trust::TrustStanding::approved`]),
/// so a restart keeps what the drift lists are judged against.
pub const KIND_CARD_APPROVAL: &str = "card_approval";

/// The host-record kinds the door's tail states (`PlaneTail::record_kinds`), in order: a record
/// write names its kind by its index here.
pub const HELD_KINDS: &[&str] = &[
    KIND_TASK,
    KIND_TASK_EVENT,
    KIND_PUSH_CONFIG,
    KIND_CARD,
    KIND_CARD_APPROVAL,
];

/// WHICH rows of a held kind a retention purge may drop: every row older than the cutoff
/// ([`Retention::Age`]), or only the TERMINAL ones ([`Retention::TerminalOnly`]), an active row
/// kept however old. The contract's `records::Retention` at f608d7d5, which the tail declared per
/// kind; busbar dev's tail states no retentions, so the plane keeps the rule here and purges by it
/// itself (what must survive a restart is records; their retention is the plane's own business).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Retention {
    /// Every row older than the cutoff.
    #[default]
    Age,
    /// Only terminal rows older than the cutoff; an active row is kept regardless of age.
    TerminalOnly,
}

impl Retention {
    /// Whether a purge under this rule drops a row stamped `ts` against the cutoff `before`, the
    /// row `terminal` or not: a row at or after the cutoff is always kept.
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
/// active (working or interrupted), so a purge drops only the terminal ones. `task_event` rows are
/// the task's chain and list no rule, as do the push configs, the cards and their approvals.
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
pub const TASK_EVENT_INDEX: u32 = 1;
