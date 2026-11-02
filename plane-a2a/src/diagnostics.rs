// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A2A plane diagnostics — the `A2A_*` catalog entries this crate OWNS.

use busbar_contract::diagnostic::{Class, Diagnostic, Severity};

/// A restored A2A task's per-task provenance chain failed verification at boot — tamper evidence.
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
    summary: "A relayed streaming request ended in a refusal rather than a normal completion, \
              including a refusal before a task context existed. The caller receives the refusal; \
              an existing task records the outcome where applicable. Per-request and expected \
              under normal backend policy, so surfaced at debug.",
    action:
        "None — self-heals. A stream that ends in a refusal reflects the backend's own decision; \
             the caller receives the refusal, with a task record when applicable.",
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

/// A relayed request failed — submissions and taskless or addressed operations alike.
pub const A2A_RELAYED_SUBMISSION_FAILED: Diagnostic = Diagnostic {
    code: 7021,
    class: Class::Plane,
    slug: "a2a-relayed-submission-failed",
    title: "Relayed A2A request failed",
    severity: Severity::BenignRecurring,
    summary:
        "A relayed request failed before completion. This includes submissions, task reads and \
              taskless operations. The caller receives the refusal; a task records the outcome \
              where applicable. Per-request and expected under normal backend policy or load, \
              so surfaced at debug.",
    action: "None — self-heals. A refused request reflects the backend's decision, capacity or \
             reachability; the caller reads the refusal and may retry the operation.",
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

/// Durable task-state restore or retention failed; normal request handling continues.
pub const A2A_TASK_STATE_UNREAD: Diagnostic = Diagnostic {
    code: 7025,
    class: Class::Plane,
    slug: "a2a-task-state-unread",
    title: "Durable A2A task state restore or retention could not complete",
    severity: Severity::Actionable,
    summary: "A durable task-store operation failed during restore or a submission's retention \
              sweep. A failed restore cannot count tasks or check their chains; a failed sweep \
              leaves retirement incomplete and does not reject the submission. Requests still \
              read their tasks individually and refuse if their own read fails. The stage field \
              identifies retention failures. Typically a durable-store outage.",
    action:
        "Investigate the durable task store outage. Submissions retry due retention work; after \
             a failed restore, restart once the store answers to count tasks and check chains.",
    since: "1.6.0",
    retired: false,
};

/// A split card or approval record was not read back whole at the card warm: the agent is looked
pub const A2A_SPLIT_RECORD_UNREAD: Diagnostic = Diagnostic {
    code: 7031,
    class: Class::Plane,
    slug: "a2a-split-record-unread",
    title: "A2A card or approval record split across host records was not read back whole",
    severity: Severity::Actionable,
    summary: "When the plane warmed its agent cards after its instance opened, a card or card \
              approval that was written split across several host records (it was larger than the \
              host's record ceiling) could not be reassembled: a part is missing, or the parts do \
              not verify against the digest the record's head states. The record is not read, so \
              that agent is looked at afresh, as if no such record were held; the record is written \
              again on the agent's next connect or approve. Emitted once per affected record on \
              each warm.",
    action: "Check the durable record store for lost or altered records (an interrupted write, a \
             store restored from an older backup, or a write from outside busbar), and the named \
             agent's card and approval state.",
    since: "1.6.0",
    retired: false,
};

/// Part records of a split card or approval that no whole record names were found at the card
pub const A2A_SPLIT_RECORD_STRAY_PARTS: Diagnostic = Diagnostic {
    code: 7032,
    class: Class::Plane,
    slug: "a2a-split-record-stray-parts",
    title: "A2A card or approval part records that no whole record names were found",
    severity: Severity::BenignRecurring,
    summary: "When the plane warmed its agent cards after its instance opened, it found part \
              records of a split card or card approval that no whole record names: left by a write \
              that was interrupted or superseded. They are never read; each is tombstoned on its \
              agent's next connect or approve. Emitted once per kind on each warm that finds any; \
              the `parts` field carries how many.",
    action: "None; self-heals. The stray parts are tombstoned when their agent's record is next \
             written. If the count grows across restarts, check the durable record store for \
             failing writes.",
    since: "1.6.0",
    retired: false,
};

/// A far end named a task id longer than the plane holds: busbar's own id stands for the task.
pub const A2A_BACKEND_TASK_ID_UNHELD: Diagnostic = Diagnostic {
    code: 7040,
    class: Class::Plane,
    slug: "a2a-backend-task-id-unheld",
    title: "A2A far-end task id longer than the plane holds was not recorded",
    severity: Severity::Actionable,
    summary: "An agent answered a task with its own task id, and that id is longer than the plane \
             holds (1024 bytes): the far end's ids are untrusted input, and the map that translates \
             them is bounded in bytes as it is in entries. The id is not recorded, so the task keeps \
             busbar's own id and a later request naming the task reaches the agent under busbar's id, \
             which the agent may not know. The `task` field carries busbar's task id and `bytes` the \
             length the agent named.",
    action: "Investigate the named agent: it issues task ids far longer than any A2A agent needs. \
            Follow-up requests on the affected tasks may be answered 'task not found' by the agent \
            until it issues ids of an ordinary length.",
    since: "1.6.0",
    retired: false,
};

/// A relayed hop's agent endpoint was refused by the relay's guard: the operator's reason.
pub const A2A_RELAY_ENDPOINT_REFUSED: Diagnostic = Diagnostic {
    code: 7041,
    class: Class::Plane,
    slug: "a2a-relay-endpoint-refused",
    title: "A2A agent endpoint refused before the hop",
    severity: Severity::Actionable,
    summary: "Before a relayed request was sent, the agent's registered url was refused by the relay's \
             guard: its scheme is plaintext on a registration without `allow_private`, or the host's \
             destination judgement refused the host or an address it resolves to. The caller is \
             answered the hop's fixed refusal words; this diagnostic carries the guard's own \
             sentence, naming the url and why, which the caller is never shown. Emitted on each \
             refused hop.",
    action: "Correct the named agent's registration: use an https:// url, or set `allow_private: \
            true` if the endpoint is a loopback or private one the operator means to reach; for a \
            refused address, check the agent's DNS and the deployment's destination policy.",
    since: "1.6.0",
    retired: false,
};

/// An agent card sighting was not recorded on the kernel's trust book: the look failed closed.
pub const A2A_TRUST_SIGHTING_UNRECORDED: Diagnostic = Diagnostic {
    code: 7042,
    class: Class::Plane,
    slug: "a2a-trust-sighting-unrecorded",
    title: "A2A agent card sighting not recorded on the kernel's trust book",
    severity: Severity::Actionable,
    summary: "The plane looked at an agent's card (on connect, approve, or the re-verification before \
             a relayed call) and reported what it saw to the kernel's trust book, and the host failed \
             that report. The kernel was never told the card's fingerprint, so its verdict still \
             answers for the card it last saw: the look fails closed, no card is held from it, and \
             the agent is not served on it (connect and approve report the failure). Emitted once per \
             failed report; the `agent` field names the agent.",
    action: "Check the host's trust service and its durable store: a trust book that cannot record \
            sightings leaves every re-verified agent refused until it can. The agent is looked at \
            again on its next call or verb.",
    since: "1.6.0",
    retired: false,
};

/// A stored card or approval record could not be read at the card warm: the agent is looked at afresh.
pub const A2A_CARD_RECORD_UNREAD: Diagnostic = Diagnostic {
    code: 7044,
    class: Class::Plane,
    slug: "a2a-card-record-unread",
    title: "A2A stored card or approval record could not be read",
    severity: Severity::Actionable,
    summary: "When the plane warmed its agent cards after its instance opened, a stored card or \
             card-approval record read back whole but is not the JSON the plane wrote (a card that is \
             not a JSON document, an approval that is not a map of skill digests). The record is not \
             used: the agent holds no card from it, so its calls are refused until it is looked at \
             again, and its approved skills are not restored for the trust view. Emitted once per \
             affected record on each warm; the `kind` and `agent` fields name it.",
    action: "Run connect (and approve, if the agent was approved) for the named agent: that writes \
            the record again. Check the durable record store for writes from outside busbar or a \
            restore from an incompatible backup.",
    since: "1.6.0",
    retired: false,
};

/// A request-stage hook's rewrite yielded no params object: the request is relayed unmodified.
pub const A2A_HOOK_REWRITE_NOT_APPLIED: Diagnostic = Diagnostic {
    code: 7045,
    class: Class::Plane,
    slug: "a2a-hook-rewrite-not-applied",
    title: "A2A request hook rewrite not applied (it yields no params object)",
    severity: Severity::Actionable,
    summary: "A request-stage hook attached to an A2A agent returned a rewrite whose messages yield no \
             JSON object to replace the request's params with (for example a content of plain text \
             such as '[REDACTED]'). As 1.5.5's rewrite contract has it, a rewrite that cannot be \
             applied leaves the request unmodified: the request is relayed with its original params. \
             The `stage` field names the hook stage.",
    action: "Check the hook: an A2A rewrite replaces the request's `params` object, so the hook must \
            return the rewritten params as a JSON object (an object content, or a JSON string that \
            parses to one). A hook meant to redact must return the redacted params, not a \
            placeholder string.",
    since: "1.6.0",
    retired: false,
};

/// A request-stage hook committed a rewrite busbar could not read back: the submission is refused.
pub const A2A_HOOK_REWRITE_UNREADABLE: Diagnostic = Diagnostic {
    code: 7046,
    class: Class::Plane,
    slug: "a2a-hook-rewrite-unreadable",
    title: "A2A request hook rewrite could not be read back; submission refused",
    severity: Severity::Actionable,
    summary: "A request-stage hook attached to an A2A agent committed a rewrite whose bytes busbar \
             could not read back (they are not JSON, or not the hook stage's messages list). The \
             submission is refused with an internal error rather than relayed with the params the \
             hook said it had replaced. The caller reads the fixed refusal; this diagnostic carries \
             the reason. The `stage` field names the hook stage.",
    action: "Check the hook's output against the hook stage's rewrite contract (a JSON object with a \
            `messages` list). Submissions to the agent keep being refused while the hook commits \
            unreadable rewrites.",
    since: "1.6.0",
    retired: false,
};

/// A2A push callback check or task transition could not complete.
pub const A2A_PUSH_CHECK_UNAVAILABLE: Diagnostic = Diagnostic {
    code: 7050,
    class: Class::Plane,
    slug: "a2a-push-check-unavailable",
    title: "A2A push callback check or task transition could not complete",
    severity: Severity::Actionable,
    summary: "A push callback could not complete a required host verification, durable task transition, store, or signer operation. This is an internal availability fault, not a caller or token refusal. The diagnostic names the failed stage so an operator can distinguish the fault from a malformed or unauthorized callback. Emitted on each such failure.",
    action: "Check the named host service and durable task store, including signer availability and the surrounding fault diagnostic; restore service before relying on callback delivery.",
    since: "1.6.0",
    retired: false,
};

/// A2A protocol_version settings are ignored by this build.
pub const A2A_PROTOCOL_VERSION_IGNORED: Diagnostic = Diagnostic {
    code: 7051,
    class: Class::Plane,
    slug: "a2a-protocol-version-ignored",
    title: "A2A protocol_version settings are ignored by this build",
    severity: Severity::Actionable,
    summary: "A successfully opened agents section contains protocol_version settings. These strings are accepted for configuration compatibility but do not pin discovery or select a protocol version; the plane discovers and reads the agent card independently of them. Emitted once per successful section open, naming only registrations and never the supplied version values.",
    action: "Remove the ignored protocol_version fields and use the agent card and supported protocol bindings to establish the peer protocol; do not rely on these fields as an enforced pin.",
    since: "1.6.0",
    retired: false,
};

/// A relayed SSE frame was not valid UTF-8 and was dropped. Frozen: `BUSBAR-7104`, the published
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
#[cfg(test)]
pub const DIAGNOSTICS: &[&Diagnostic] = &[
    &A2A_TASK_CHAIN_VERIFY_FAILED,
    &A2A_POOL_NOT_INTERCHANGEABLE,
    &A2A_OUTBOUND_CRED_UNLEASED,
    &A2A_RELAYED_STREAM_REFUSED,
    &A2A_RELAYED_OUTCOME_UNRECORDED,
    &A2A_RELAYED_SUBMISSION_FAILED,
    &A2A_FAILURE_UNRECORDED,
    &A2A_TASK_ROWS_UNREADABLE,
    &A2A_TASK_STATE_UNREAD,
    &A2A_SPLIT_RECORD_UNREAD,
    &A2A_SPLIT_RECORD_STRAY_PARTS,
    &A2A_BACKEND_TASK_ID_UNHELD,
    &A2A_RELAY_ENDPOINT_REFUSED,
    &A2A_TRUST_SIGHTING_UNRECORDED,
    &A2A_CARD_RECORD_UNREAD,
    &A2A_HOOK_REWRITE_NOT_APPLIED,
    &A2A_HOOK_REWRITE_UNREADABLE,
    &A2A_PUSH_CHECK_UNAVAILABLE,
    &A2A_PROTOCOL_VERSION_IGNORED,
    &PLANE_SSE_FRAME_NOT_UTF8,
];

#[cfg(test)]
#[path = "tests/diagnostics_tests.rs"]
mod diagnostics_tests;
