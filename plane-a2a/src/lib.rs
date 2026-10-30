//! The A2A plane: the agent-to-agent protocol, spelled two ways (v0.3 and v1.0) over three
//! bindings (JSON-RPC, HTTP+JSON and gRPC), as one plugin door ([`door`]).
//!
//! ## What this crate is
//!
//! The whole plane. Its wire reading and writing (the JSON-RPC envelope, the HTTP+JSON request
//! line, the gRPC line's generated messages), its task vocabulary, its error table and its record
//! kinds live here; no other crate holds an A2A codec it adapts.
//!
//! ## What this crate is not
//!
//! It holds no governance, no breaker, no hook seat, no signing key and no arithmetic over a metered
//! quantity. Those are the kernel's. The plane reports UNITS (where the numbers are, and the number
//! it read) and never a price, a hold or a decision; it opens no socket, reads no file and reads no
//! clock but the one the kernel hands it. Every connection it needs is the host's, on a need its
//! Statement declares.
//!
//! ## What it holds across calls
//!
//! State, and all of it in the SDK's `Keyed` maps on the door's instance: the units in flight, the
//! held agent cards and their trust, the agents' own task ids, the push deliveries and the mirror
//! flights. What must survive a restart is a host record, never a map entry: the maps are what the
//! instance holds between two calls, rebuilt from the records when it opens. No cell, lock, atomic
//! or global of the plane's own sits beside them (a source scan holds that).

#![forbid(unsafe_code)]
#![deny(missing_docs)]

/// The wire dialect's own modules (the card, the config grammar, the credentials, the public URL
/// and the task), under their own `a2a::` parent.
mod a2a {
    pub mod agent_card;
    pub mod canonical;
    pub mod card;
    pub mod config;
    pub mod creds;
    pub mod public;
    pub mod task;
}

mod agent_arrival;
mod answer_bytes;
mod binding;
mod card_trust;
mod cards;
mod claims;
mod diagnostics;
mod events;
mod framed;
mod local;
mod mirror;
mod ops;
/// THE DOOR's module: the plane door the root re-exports as [`door`].
mod plane_door;
mod proto;
mod push;
mod push_door;
mod push_serve;
mod record;
mod records;
mod relay;
mod rest;
mod served_card;
mod skill;
mod split_record;
mod sse;
mod statement;
mod task_door;
mod task_hop;
mod task_identity;
mod tasks;
mod wkt;

/// The door: this plugin's one public item.
pub use plane_door::door;

/// The task and task-event row structs at the crate root, where the task type names them.
use record::{TaskEventRow, TaskRow};

// ══ THE A2A WIRE VOCABULARY ══════════════════════════════════════════════════════════════════════
//
// Definition 16-20: everything ONE protocol needs and no other protocol may name — its wire
// dialects, its decode/encode face. Every name below is a fact about the A2A wire and about nothing
// else: the registry key, the config section it owns, the mount, the gRPC service path the protocol
// (not busbar) chose, the eight routes, the well-known card path, the protected-resource metadata
// path, the push suffix, the A2A error band with its `ErrorInfo.reason` tokens, and the local verb
// method names in both dialect spellings.
//
// Each is spelled once, here, and every place the plane states or answers it reads this spelling.

/// THE REGISTRY KEY A2A IS KNOWN BY, in the plane registry and in the plugin contract alike.
///
/// Named ONCE, here: the door's Statement and every test that reads the plane's key read this one.
const PLANE_KEY: &str = "a2a";

/// THE CONFIGURATION SECTION THIS PLANE OWNS, named once for the same reason [`PLANE_KEY`] is: the
/// Statement declares it and the section's grammar reads under it.
const CONFIG_SECTION: &str = "agents";

/// THE PLANE'S MOUNT, the path prefix the A2A plane's HTTP bindings are served under. Every route
/// this plane serves over HTTP is under it, and the host's plane dispatch matches on it at a segment
/// boundary, so `/a2ax` is somebody else's path.
///
/// One constant, read everywhere the mount is spelled: the plane's path claims, the agent
/// endpoints its served cards publish and the protected-resource metadata path are all composed
/// from it, so the claimed mount and the published one cannot be two strings.
const MOUNT_PATH: &str = "/a2a";

// ══ THE ROUTES THIS PLANE SERVES, SPELLED EXACTLY ONCE ══════════════════════════════════════════
//
// Every path below is spelled once and read twice: the door's Statement CLAIMS it, and the
// plane's own arrival reader ANSWERS it, so a route the plane answers is a route it claims and a
// claim is never a path nothing answers. The suffixes are relative to [`MOUNT_PATH`] and carry
// their capture names verbatim (`{id}`, `{config_id}`), the A2A HTTP+JSON binding's own.

/// `POST` — the message-send operation.
const ROUTE_MESSAGE_SEND: &str = "/message:send";
/// `POST` — the same body, the streaming method, an SSE answer.
const ROUTE_MESSAGE_STREAM: &str = "/message:stream";
/// `GET` — the task list; its filters ride the query string.
const ROUTE_TASKS: &str = "/tasks";
/// `GET` one task, and `POST` the colon-suffixed verbs against it. ONE template, two methods: the
/// router merges methods for one path, and two templates differing only in the capture NAME are one
/// pattern registered twice, which is a startup panic rather than a route.
const ROUTE_TASK: &str = "/tasks/{id}";
/// `POST` a push-notification config, `GET` the list.
const ROUTE_PUSH_CONFIGS: &str = "/tasks/{id}/pushNotificationConfigs";
/// `GET` and `DELETE` one push-notification config.
const ROUTE_PUSH_CONFIG: &str = "/tasks/{id}/pushNotificationConfigs/{config_id}";
/// `GET` — the extended agent card.
const ROUTE_EXTENDED_AGENT_CARD: &str = "/extendedAgentCard";
/// One FRONTED agent's endpoint, derived from the agent id so a caller's endpoint is stable and
/// says which agent it reaches.
const ROUTE_AGENT: &str = "/agents/{agent_id}";
/// One FRONTED agent's own card, at the protocol's well-known discovery path under the agent's
/// endpoint (R-15): a client handed the agent's endpoint discovers its card there, and the card's
/// `url` names that endpoint.
const ROUTE_AGENT_CARD: &str = "/agents/{agent_id}/.well-known/agent-card.json";

/// THE PROTOCOL'S CANONICAL CARD DISCOVERY PATH, from protocol v0.3 onward. Absolute, not under
/// [`MOUNT_PATH`]: a well-known path is a property of the ORIGIN.
const WELL_KNOWN_CARD_PATH: &str = "/.well-known/agent-card.json";

/// THE RFC 9728 PROTECTED-RESOURCE METADATA PATH for this plane — the well-known prefix with the
/// plane's mount appended, exactly as the sibling plane composes its own.
const METADATA_PATH: &str = "/.well-known/oauth-protected-resource/a2a";

/// THE SUFFIX OF BUSBAR'S OWN PUSH CALLBACK under [`MOUNT_PATH`]: `/a2a/push`, the URL a mirrored
/// push config names at the agent. It is served as busbar's own PUBLIC route
/// ([`statement::PUSH_ROUTE`]), never as one of the plane's claims.
const PUSH_PATH_SUFFIX: &str = "/push";

/// [`MOUNT_PATH`] joined to one of the route suffixes above. One join, called from both sides,
/// so the served route and the plane's claim cannot be two different strings.
#[must_use]
fn mounted_route(suffix: &str) -> String {
    format!("{MOUNT_PATH}{suffix}")
}

/// THE A2A-SPECIFIC ERROR CODES, each with the `ErrorInfo.reason` it is reported under.
///
/// The A2A-specific band is `-32001..=-32099`; the standard JSON-RPC codes are NOT here, because
/// the specification's own table leaves their reason UNSET and inventing one would put a word on
/// the wire the specification does not define.
///
/// One table: every A2A-defined code the plane writes is read from it, with its reason, on the
/// JSON-RPC line, the HTTP+JSON line and the gRPC line's status details.
const ERRORS: &[(i64, &str)] = &[
    (-32001, "TASK_NOT_FOUND"),
    (-32002, "TASK_NOT_CANCELABLE"),
    (-32003, "PUSH_NOTIFICATION_NOT_SUPPORTED"),
    (-32004, "UNSUPPORTED_OPERATION"),
    (-32005, "CONTENT_TYPE_NOT_SUPPORTED"),
    (-32006, "INVALID_AGENT_RESPONSE"),
    (-32007, "EXTENDED_AGENT_CARD_NOT_CONFIGURED"),
    (-32008, "EXTENSION_SUPPORT_REQUIRED"),
    (-32009, "VERSION_NOT_SUPPORTED"),
];

/// The `@type` of the detail entry an A2A error carries in `error.data` — `google.rpc.ErrorInfo`,
/// spelled as the protobuf type URL the specification names.
const ERROR_INFO_TYPE: &str = "type.googleapis.com/google.rpc.ErrorInfo";

/// The `ErrorInfo.domain` every A2A error is reported under. The protocol's own, not busbar's: the
/// reason tokens above are the specification's vocabulary and the domain says so.
const ERROR_INFO_DOMAIN: &str = "a2a-protocol.org";

/// The crate's tests that reach past [`door`]: once integration tests (`tests/*.rs`), now in-crate
/// because the crate's only public item is the door.
#[cfg(test)]
mod tests {
    /// The crate's one `#[global_allocator]`, every allocation gate's count: busbar-test-kit's
    /// `alloc_counter` (a dev-dependency), so this crate holds no `unsafe`.
    #[global_allocator]
    static A: busbar_test_kit::alloc_counter::Counting =
        busbar_test_kit::alloc_counter::Counting::new();

    mod alloc_gate;
    pub(crate) mod capture;
    mod conformance;
    mod door_facts;
    mod purity;
}
