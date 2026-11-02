// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CANONICAL TASK: busbar's own struct for the unit of work A2A calls a Task, and the state

#![cfg_attr(not(test), allow(dead_code))]

use serde::{Deserialize, Serialize};

/// Which side of the hop this task is. Persisted, because the two directions RESUME differently
/// after a restart: an inbound task re-establishes the relay to the caller that submitted it, an
/// outbound one re-subscribes to the remote agent it was delegated to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    /// busbar is the server: an external caller delegated work to a busbar-fronted agent.
    Inbound,
    /// busbar is the client: a fronted agent delegated work to a registered remote agent.
    Outbound,
}

impl Direction {
    /// The stable wire/store token. Config, admin responses, audit rows and store rows all spell it

    pub fn as_str(self) -> &'static str {
        match self {
            Direction::Inbound => "inbound",
            Direction::Outbound => "outbound",
        }
    }

    /// Parse a stored token. An UNKNOWN token is an error rather than a default, because defaulting

    pub fn parse(s: &str) -> Result<Self, TaskError> {
        match s {
            "inbound" => Ok(Direction::Inbound),
            "outbound" => Ok(Direction::Outbound),
            other => Err(TaskError::UnknownDirection(other.to_string())),
        }
    }
}

/// The A2A task lifecycle states busbar runs, spelled exactly as the protocol spells them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TaskState {
    /// Accepted, not yet started.
    Submitted,
    /// Running.
    Working,
    /// PAUSED awaiting caller input. Not an ending.
    InputRequired,
    /// PAUSED awaiting caller authentication/authorization. Not an ending.
    AuthRequired,
    /// Terminal: finished successfully.
    Completed,
    /// Terminal: finished unsuccessfully.
    Failed,
    /// Terminal: stopped on request.
    Canceled,
    /// Terminal: refused before doing the work.
    Rejected,
}

impl TaskState {
    /// The stable wire/store token.
    pub fn as_str(self) -> &'static str {
        match self {
            TaskState::Submitted => "submitted",
            TaskState::Working => "working",
            TaskState::InputRequired => "input-required",
            TaskState::AuthRequired => "auth-required",
            TaskState::Completed => "completed",
            TaskState::Failed => "failed",
            TaskState::Canceled => "canceled",
            TaskState::Rejected => "rejected",
        }
    }

    /// Parse a stored token, refusing an unknown one.

    pub fn parse(s: &str) -> Result<Self, TaskError> {
        match s {
            "submitted" => Ok(TaskState::Submitted),
            "working" => Ok(TaskState::Working),
            "input-required" => Ok(TaskState::InputRequired),
            "auth-required" => Ok(TaskState::AuthRequired),
            "completed" => Ok(TaskState::Completed),
            "failed" => Ok(TaskState::Failed),
            "canceled" => Ok(TaskState::Canceled),
            "rejected" => Ok(TaskState::Rejected),
            other => Err(TaskError::UnknownState(other.to_string())),
        }
    }

    /// A state nothing leaves.
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            TaskState::Completed | TaskState::Failed | TaskState::Canceled | TaskState::Rejected
        )
    }

    /// PAUSED awaiting the caller. Distinct from terminal AND from active: an interrupted task

    pub fn is_interrupted(self) -> bool {
        matches!(self, TaskState::InputRequired | TaskState::AuthRequired)
    }

    /// Is `to` a legal move from `self`?

    pub fn can_transition_to(self, to: TaskState) -> bool {
        use TaskState::*;
        match self {
            Submitted => matches!(
                to,
                Working | InputRequired | AuthRequired | Completed | Failed | Canceled | Rejected
            ),

            Working => matches!(
                to,
                InputRequired | AuthRequired | Completed | Failed | Canceled | Rejected
            ),

            InputRequired => matches!(
                to,
                Working | AuthRequired | Completed | Failed | Canceled | Rejected
            ),
            AuthRequired => matches!(
                to,
                Working | InputRequired | Completed | Failed | Canceled | Rejected
            ),

            Completed | Failed | Canceled | Rejected => false,
        }
    }
}

/// What went wrong reading or moving a task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskError {
    /// A stored state token this binary does not know (see [`TaskState::parse`]).
    UnknownState(String),
    /// A stored direction token this binary does not know.
    UnknownDirection(String),
    /// The move is not in the transition table.
    IllegalTransition {
        /// The state token the task was in.
        from: &'static str,
        /// The state token the move asked for.
        to: &'static str,
    },
    /// A row with no `task_id`, `context_id` or `principal`. Refused on the way IN rather than
    /// discovered on the way out: an empty `principal` is a task nobody can be shown and nobody can
    /// be billed for, and an empty `task_id` collides with the next one.
    MissingIdentity(&'static str),
}

impl std::fmt::Display for TaskError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TaskError::UnknownState(s) => write!(
                f,
                "unknown task state `{s}`: this row was written by a different engine version and \
                 cannot be classified as terminal or interrupted, so it is refused rather than \
                 guessed at"
            ),
            TaskError::UnknownDirection(s) => write!(f, "unknown task direction `{s}`"),
            TaskError::IllegalTransition { from, to } => {
                write!(f, "illegal task transition `{from}` -> `{to}`")
            }
            TaskError::MissingIdentity(which) => {
                write!(f, "task is missing its `{which}`")
            }
        }
    }
}

/// THE CANONICAL TASK ROW. Exactly the fields that decide how an in-flight task RESUMES after a
/// restart — who it belongs to, what state it is in, which agent it went to, and how far its
/// artifact stream got — plus the two timestamps the retention policy reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Task {
    /// busbar's own task id.
    pub task_id: String,
    /// The A2A context the task belongs to.
    pub context_id: String,
    /// The principal the task belongs to: the only caller it is ever shown to.
    pub principal: String,
    /// Whether busbar received the task or delegated it.
    pub direction: Direction,
    /// Where the task is in its lifecycle.
    pub state: TaskState,
    /// The chosen (outbound) or fronted (inbound) agent id; empty before dispatch.
    pub agent_id: String,
    /// How many artifact chunks have been durably relayed — the resubscribe resume point.
    pub artifact_cursor: u64,
    /// The registered push-notification callback for this task, or `None`. Already SSRF-validated
    /// when it was registered (see the plane's push-notification guard); it is re-validated before
    /// delivery, because the row can outlive the DNS answer that was checked when it was written.
    pub push_callback: Option<String>,
    /// The A2A version `push_callback` was registered under (`0.3` or `1.0`; empty reads as
    /// `1.0`): the shape every notification to it takes.
    pub push_version: String,
    /// When the task was submitted, in whole seconds since the Unix epoch.
    pub created_at: u64,
    /// When the task last changed, in whole seconds since the Unix epoch.
    pub updated_at: u64,
}

impl Task {
    /// A freshly SUBMITTED task. The only constructor that invents a state, so every other path has

    pub fn submitted(
        task_id: impl Into<String>,
        context_id: impl Into<String>,
        principal: impl Into<String>,
        direction: Direction,
        now: u64,
    ) -> Result<Self, TaskError> {
        let task = Task {
            task_id: task_id.into(),
            context_id: context_id.into(),
            principal: principal.into(),
            direction,
            state: TaskState::Submitted,
            agent_id: String::new(),
            artifact_cursor: 0,
            push_callback: None,
            push_version: String::new(),
            created_at: now,
            updated_at: now,
        };
        task.check_identity()?;
        Ok(task)
    }

    fn check_identity(&self) -> Result<(), TaskError> {
        if self.task_id.is_empty() {
            return Err(TaskError::MissingIdentity("task_id"));
        }
        if self.context_id.is_empty() {
            return Err(TaskError::MissingIdentity("context_id"));
        }
        if self.principal.is_empty() {
            return Err(TaskError::MissingIdentity("principal"));
        }
        Ok(())
    }

    /// Move to `to`, or refuse. `updated_at` moves only on a move that was ACCEPTED, so the

    pub fn transition_to(&mut self, to: TaskState, now: u64) -> Result<(), TaskError> {
        if !self.state.can_transition_to(to) {
            return Err(TaskError::IllegalTransition {
                from: self.state.as_str(),
                to: to.as_str(),
            });
        }
        self.state = to;
        self.updated_at = now;
        Ok(())
    }

    /// Project onto the store seam.
    pub fn to_row(&self) -> crate::TaskRow {
        crate::TaskRow {
            task_id: self.task_id.clone(),
            context_id: self.context_id.clone(),
            principal: self.principal.clone(),
            direction: self.direction.as_str().to_string(),
            state: self.state.as_str().to_string(),
            agent_id: self.agent_id.clone(),
            artifact_cursor: self.artifact_cursor,
            push_callback: self.push_callback.clone().unwrap_or_default(),
            push_version: self.push_version.clone(),
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }

    /// Read back from the store seam, validating every field that has a closed domain. A row that

    pub fn from_row(row: &crate::TaskRow) -> Result<Self, TaskError> {
        let task = Task {
            task_id: row.task_id.clone(),
            context_id: row.context_id.clone(),
            principal: row.principal.clone(),
            direction: Direction::parse(&row.direction)?,
            state: TaskState::parse(&row.state)?,
            agent_id: row.agent_id.clone(),
            artifact_cursor: row.artifact_cursor,
            push_callback: if row.push_callback.is_empty() {
                None
            } else {
                Some(row.push_callback.clone())
            },
            push_version: row.push_version.clone(),
            created_at: row.created_at,
            updated_at: row.updated_at,
        };
        task.check_identity()?;
        Ok(task)
    }
}

/// Map an A2A state transition to its provenance event kind. The neutral core only hash-chains and

pub fn event_kind_for_transition(from: TaskState, to: TaskState) -> &'static str {
    use busbar_contract::vocab::{EV_INTERRUPTED, EV_RESUMED, EV_TERMINAL, EV_WORKING};
    match to {
        TaskState::Working if from.is_interrupted() => EV_RESUMED,
        TaskState::Working => EV_WORKING,
        TaskState::InputRequired | TaskState::AuthRequired => EV_INTERRUPTED,
        TaskState::Completed | TaskState::Failed | TaskState::Canceled | TaskState::Rejected => {
            EV_TERMINAL
        }
        TaskState::Submitted => EV_WORKING,
    }
}

/// THE TRANSITION PLAN the neutral engine applies under its working-set lock. Given the CURRENT

pub fn plan_transition(
    to: TaskState,
    now: u64,
) -> impl FnOnce(&crate::TaskRow) -> Result<(crate::TaskRow, &'static str), String> {
    move |row| {
        let mut task = Task::from_row(row).map_err(|e| e.to_string())?;

        let kind = event_kind_for_transition(task.state, to);
        task.transition_to(to, now).map_err(|e| e.to_string())?;
        Ok((task.to_row(), kind))
    }
}

/// The restore-row readability predicate the neutral rehydrate consults. Answers `Ok(())`

pub fn readable_row(row: &crate::TaskRow) -> Result<(), String> {
    Task::from_row(row).map(|_| ()).map_err(|e| e.to_string())
}

#[cfg(test)]
#[path = "tests/task_tests.rs"]
mod task_tests;
