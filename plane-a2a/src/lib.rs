// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The A2A plane: the agent-to-agent protocol, spelled two ways (v0.3 and v1.0) over three

#![forbid(unsafe_code)]
#![deny(missing_docs)]

/// The wire dialect's own modules (the card, the config grammar, the credentials, the public URL
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
mod conditional_publication;
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
mod record_custody;
mod records;
mod relay;
mod request_json;
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

/// The SDK macro's proof of this same door, for external conformance fixtures.
#[doc(hidden)]
pub use plane_door::MACRO_DOOR;

/// This plane's embedded declarations, shared by linked and dynamic metadata.
pub const DECLARES: &str = include_str!("../declares.json");

/// The task and task-event row structs at the crate root, where the task type names them.
use record::{TaskEventRow, TaskRow};

/// THE REGISTRY KEY A2A IS KNOWN BY, in the plane registry and in the plugin contract alike.
const PLANE_KEY: &str = "a2a";

/// THE CONFIGURATION SECTION THIS PLANE OWNS, named once for the same reason [`PLANE_KEY`] is: the
const CONFIG_SECTION: &str = "agents";

/// THE PLANE'S MOUNT, the path prefix the A2A plane's HTTP bindings are served under. Every route
const MOUNT_PATH: &str = "/a2a";

/// `POST` — the message-send operation.
const ROUTE_MESSAGE_SEND: &str = "/message:send";
/// `POST` — the same body, the streaming method, an SSE answer.
const ROUTE_MESSAGE_STREAM: &str = "/message:stream";
/// `GET` — the task list; its filters ride the query string.
const ROUTE_TASKS: &str = "/tasks";
/// `GET` one task, and `POST` the colon-suffixed verbs against it. ONE template, two methods: the
const ROUTE_TASK: &str = "/tasks/{id}";
/// `POST` a push-notification config, `GET` the list.
const ROUTE_PUSH_CONFIGS: &str = "/tasks/{id}/pushNotificationConfigs";
/// `GET` and `DELETE` one push-notification config.
const ROUTE_PUSH_CONFIG: &str = "/tasks/{id}/pushNotificationConfigs/{config_id}";
/// `GET` — the extended agent card.
const ROUTE_EXTENDED_AGENT_CARD: &str = "/extendedAgentCard";
/// One FRONTED agent's endpoint, derived from the agent id so a caller's endpoint is stable and
const ROUTE_AGENT: &str = "/agents/{agent_id}";
/// One FRONTED agent's own card, at the protocol's well-known discovery path under the agent's
const ROUTE_AGENT_CARD: &str = "/agents/{agent_id}/.well-known/agent-card.json";

/// THE PROTOCOL'S CANONICAL CARD DISCOVERY PATH, from protocol v0.3 onward. Absolute, not under
const WELL_KNOWN_CARD_PATH: &str = "/.well-known/agent-card.json";

/// THE RFC 9728 PROTECTED-RESOURCE METADATA PATH for this plane — the well-known prefix with the
const METADATA_PATH: &str = "/.well-known/oauth-protected-resource/a2a";

/// THE SUFFIX OF BUSBAR'S OWN PUSH CALLBACK under [`MOUNT_PATH`]: `/a2a/push`, the URL a mirrored
const PUSH_PATH_SUFFIX: &str = "/push";

/// [`MOUNT_PATH`] joined to one of the route suffixes above. One join, called from both sides,
#[must_use]
fn mounted_route(suffix: &str) -> String {
    format!("{MOUNT_PATH}{suffix}")
}

/// THE A2A-SPECIFIC ERROR CODES, each with the `ErrorInfo.reason` it is reported under.
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
const ERROR_INFO_TYPE: &str = "type.googleapis.com/google.rpc.ErrorInfo";

/// The `ErrorInfo.domain` every A2A error is reported under. The protocol's own, not busbar's: the
const ERROR_INFO_DOMAIN: &str = "a2a-protocol.org";

/// The crate's tests that reach past [`door`]: once integration tests (`tests/*.rs`), now in-crate
#[cfg(test)]
mod tests {
    /// The crate's one `#[global_allocator]`, every allocation gate's count: busbar-test-kit's
    #[global_allocator]
    static A: busbar_test_kit::alloc_counter::Counting =
        busbar_test_kit::alloc_counter::Counting::new();

    mod alloc_gate;
    pub(crate) mod capture;
    mod codec_custody_cases;
    mod conformance;
    mod door_facts;
    mod purity;
    pub(crate) mod raw_custody_probe;
    pub(crate) mod request_custody_probe;
}
