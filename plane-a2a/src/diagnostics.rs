// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A2A plane diagnostics — the `A2A_*` catalog entries this crate OWNS.
//!
//! These consts are plane-specific vocabulary, so the host's neutral catalog names no `A2A_*`
//! diagnostic. Each keeps its stable `BUSBAR-NNNN` number and slug: codes are REGISTERED, never
//! renumbered or collapsed.
//!
//! [`DIAGNOSTICS`] is every code the plane raises, and the plane's `declares.json` states exactly
//! those entries (a test holds the two equal): the declares document rides the door's Statement, and
//! the host installs a plane's codes from it, in a build that links the plane and in one that loads
//! it dropped in alike. The codes the plane's predecessor registered and the plane no longer raises
//! are held by its tests (`RESERVED`): never declared, and never reissued to another meaning.

use busbar_contract::diagnostic::{Class, Diagnostic, Severity};

/// A restored A2A task's per-task provenance chain failed verification at boot — tamper evidence.
/// Lives in `a2a/mod.rs`, but the subject is the provenance chain's integrity, so it is a 2000 code.
pub const A2A_TASK_CHAIN_VERIFY_FAILED: Diagnostic = Diagnostic {
    code: 2030,
    class: Class::Audit,
    slug: "a2a-task-chain-verify-failed",
    title: "A2A per-task provenance chain failed verification on restore (tamper evidence)",
    severity: Severity::Actionable,
    summary: "When the plane restored its task records after its instance opened, an in-flight \
              task's per-task provenance chain did NOT verify: the host reported a break on that \
              task's chain. This is distinct from a row that merely could not be read \
              (BUSBAR-7024): the bytes were read and the chain does not add up, which is tamper \
              evidence — the durable task state was altered out from under busbar, or its store is \
              corrupt. The task is still held and served: a break is reported, never a deletion, \
              because deleting on a break would let anyone able to write the store erase a \
              caller's task. Emitted once per affected in-flight task on each restore.",
    action: "Treat the durable A2A task store as compromised until explained: capture it for \
             forensic review before it is overwritten, and restore it from a trusted backup once \
             the cause is understood. The named task stays held; other tasks are unaffected.",
    since: "1.6.0",
    retired: false,
};

/// A pool's members are not interchangeable, so a fresh submission is not accepted — routine refusal.
pub const A2A_POOL_NOT_INTERCHANGEABLE: Diagnostic = Diagnostic {
    code: 7003,
    class: Class::Plane,
    slug: "a2a-pool-not-interchangeable",
    title: "A2A submission not accepted (the pool's members are not interchangeable)",
    severity: Severity::BenignRecurring,
    summary: "A submission targeted an agent pool whose members are not interchangeable under the \
              seam's rules, so it was not accepted. A routine per-request routing refusal, benign and \
              expected under the configured pool policy; surfaced at debug so a busy caller cannot \
              spam the log.",
    action: "None — self-heals. If submissions should route, configure the pool's members to be \
             interchangeable (matching capabilities) so the seam can dispatch across them.",
    since: "1.6.0",
    retired: false,
};

/// An outbound credential could not be leased for a hop — an egress-auth wiring problem.
pub const A2A_OUTBOUND_CRED_UNLEASED: Diagnostic = Diagnostic {
    code: 7013,
    class: Class::Plane,
    slug: "a2a-outbound-cred-unleased",
    title: "Outbound A2A credential could not be leased",
    severity: Severity::Actionable,
    summary: "busbar could not lease the outbound credential needed to make a hop to the target \
              agent, so the hop is refused. The egress-auth path that mints or fetches the credential \
              for this agent failed. Usually an egress-auth wiring or credential-source problem.",
    action: "Check the egress-auth configuration and credential source for the named agent (scopes, \
             the credential plugin/store). Outbound hops resume once a credential can be leased.",
    since: "1.6.0",
    retired: false,
};

/// A relayed stream ended in a refusal — a per-request backend refusal on the streaming path.
pub const A2A_RELAYED_STREAM_REFUSED: Diagnostic = Diagnostic {
    code: 7018,
    class: Class::Plane,
    slug: "a2a-relayed-stream-refused",
    title: "Relayed A2A stream ended in a refusal",
    severity: Severity::BenignRecurring,
    summary: "A relayed streaming task ended in a refusal from the backend rather than a normal \
              completion. The refusal is recorded against the task and the caller's poll will find \
              it. Per-request and expected under normal backend policy, so surfaced at debug.",
    action:
        "None — self-heals. A stream that ends in a refusal reflects the backend's own decision; \
             the recorded refusal is what the caller reads.",
    since: "1.6.0",
    retired: false,
};

/// A relayed task's outcome could not be recorded — usually a store outage; the hop still succeeded.
pub const A2A_RELAYED_OUTCOME_UNRECORDED: Diagnostic = Diagnostic {
    code: 7020,
    class: Class::Plane,
    slug: "a2a-relayed-outcome-unrecorded",
    title: "Relayed A2A task outcome could not be recorded (durable store write failed)",
    severity: Severity::Actionable,
    summary: "A relayed hop SUCCEEDED and the caller is owed its answer, but the resulting state \
              transition could not be written to the durable task store. Reported, never fatal: a \
              store that refused the transition is an operator problem, not a reason to discard \
              completed, billed work. Warned once on the transition; subsequent failures hold at debug.",
    action: "Investigate the durable task-store outage. The caller still receives the completed hop; \
             only the durable outcome record failed and resumes once the store accepts writes.",
    since: "1.6.0",
    retired: false,
};

/// A relayed task submission failed at the backend — a per-request backend refusal.
pub const A2A_RELAYED_SUBMISSION_FAILED: Diagnostic = Diagnostic {
    code: 7021,
    class: Class::Plane,
    slug: "a2a-relayed-submission-failed",
    title: "Relayed A2A task submission failed",
    severity: Severity::BenignRecurring,
    summary:
        "A relayed task submission was refused by the backend. The refusal is recorded against \
              the task and returned to the caller; busbar did not accept work it could not place. \
              Per-request and expected under normal backend policy or load, so surfaced at debug.",
    action:
        "None — self-heals. A submission the backend refuses reflects the backend's own decision \
             or capacity; the caller reads the recorded refusal and may re-submit.",
    since: "1.6.0",
    retired: false,
};

/// A failed task could not be recorded as failed — usually a store outage; the caller is still answered.
pub const A2A_FAILURE_UNRECORDED: Diagnostic = Diagnostic {
    code: 7023,
    class: Class::Plane,
    slug: "a2a-failure-unrecorded",
    title: "Failed A2A task could not be recorded as failed (durable store write failed)",
    severity: Severity::Actionable,
    summary:
        "A task reached the terminal `failed` state but that transition could not be written to \
              the durable task store, so a durable row may still claim the work is in flight. The \
              caller is answered and any registered callback is fired; the durable record is what \
              failed. Typically a store outage. Warned once on the transition; then held at debug.",
    action: "Investigate the durable task-store outage. The caller was told of the failure; the \
             durable `failed` record resumes once the store accepts writes.",
    since: "1.6.0",
    retired: false,
};

/// Persisted A2A task rows could not be read back at boot and are NOT resumable — version mismatch.
pub const A2A_TASK_ROWS_UNREADABLE: Diagnostic = Diagnostic {
    code: 7024,
    class: Class::Plane,
    slug: "a2a-task-rows-unreadable",
    title: "Persisted A2A task rows could not be read back (not resumable)",
    severity: Severity::Actionable,
    summary: "When the plane restored its task records after its instance opened, some persisted \
              A2A task rows could not be read back and are therefore NOT resumable — most likely \
              written by a different busbar version. Reported separately from the restored count \
              and at warn, because folding an unreadable in-flight task into the restored total is \
              how a task that silently ceased to exist across a deploy stays invisible.",
    action: "Expected once after a version change; the counted rows cannot be resumed by this \
             binary. If it recurs without a version change, inspect the durable task store for \
             corruption. Callers of the affected tasks may re-submit.",
    since: "1.6.0",
    retired: false,
};

/// Durable A2A task state could not be read at boot; in-flight tasks start empty — a store outage.
pub const A2A_TASK_STATE_UNREAD: Diagnostic = Diagnostic {
    code: 7025,
    class: Class::Plane,
    slug: "a2a-task-state-unread",
    title: "Durable A2A task state could not be read on restore (nothing counted or chain-checked)",
    severity: Severity::Actionable,
    summary: "When the plane restored its task records after its instance opened, the durable A2A \
              task records could not be listed at all, so nothing was counted and no in-flight \
              task's provenance chain was checked. Serving does not wait on the restore: each task \
              is still read from its own record when a request names it, and a request the store \
              cannot answer is refused. Typically a durable-store outage.",
    action:
        "Investigate the durable task store outage. Once it answers, requests read their tasks \
             again; restart to have the restore count the tasks and check their chains.",
    since: "1.6.0",
    retired: false,
};

/// A relayed SSE frame was not valid UTF-8 and was dropped. Frozen: `BUSBAR-7104`, the published
/// catalog entry of the same number, byte for byte.
pub const PLANE_SSE_FRAME_NOT_UTF8: Diagnostic = Diagnostic {
    code: 7104,
    class: Class::Plane,
    slug: "plane-sse-frame-not-utf8",
    title: "A relayed SSE frame was not valid UTF-8 and was dropped",
    severity: Severity::Actionable,
    summary: "The shared SSE frame reader (the JSON-RPC plane relays) assembled a complete event \
              whose bytes are not valid UTF-8. The event-stream format is UTF-8 BY DEFINITION, so \
              this is a malformed backend; the frame is DROPPED rather than lossily transcoded, \
              which would hand the client a corrupted payload. The stream itself continues, so a \
              client sees a missing event, not a failure. The `bytes` field carries the size of \
              the frame that was dropped.",
    action: "Investigate the named backend agent: its event stream is emitting non-UTF-8 bytes, \
             which no conforming event-stream consumer can read. Until it is fixed the affected \
             events are lost; busbar relays every well-formed event around them.",
    since: "1.6.0",
    retired: false,
};

/// THE CODES THE PLANE RAISES, ascending by code: every entry its source reports through
/// `diag_*!`, and exactly the `diagnostics` its `declares.json` states (a test holds the three
/// equal), from which the host installs them in either build. `BUSBAR-7104` came out of the host
/// registry with the relay's frame reader that emits it, under its frozen number.
pub static DIAGNOSTICS: &[&Diagnostic] = &[
    &A2A_TASK_CHAIN_VERIFY_FAILED,
    &A2A_POOL_NOT_INTERCHANGEABLE,
    &A2A_OUTBOUND_CRED_UNLEASED,
    &A2A_RELAYED_STREAM_REFUSED,
    &A2A_RELAYED_OUTCOME_UNRECORDED,
    &A2A_RELAYED_SUBMISSION_FAILED,
    &A2A_FAILURE_UNRECORDED,
    &A2A_TASK_ROWS_UNREADABLE,
    &A2A_TASK_STATE_UNREAD,
    &PLANE_SSE_FRAME_NOT_UTF8,
];

#[cfg(test)]
#[path = "tests/diagnostics_tests.rs"]
mod diagnostics_tests;
