// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DOOR'S FACTS THE DOOR-DRIVEN TESTS NAME (`tests/unit_lifetime.rs`, `tests/project_session.rs`,
//! and the plugin crate's both-ways script `plane-a2a-plugin/tests/both_ways.rs`). Those tests drive
//! the plane only through [`door`](busbar_plane_a2a::door), the crate's one public item, and need a
//! few of its private constants to build their inputs and read its answers. They are restated here,
//! plain data, and the crate's own unit test `door_facts` (`src/tests/door_facts.rs`) includes this
//! same file and asserts every value equals the private item it restates, so a drift is red in the
//! crate before a door-driven test reads a stale value.

/// `agent_door::MAX_UNITS`: the most units the instance keeps state for at once.
pub const MAX_UNITS: usize = 4096;

/// `door_statement::DIALECT_DOCUMENT`: the JSON-RPC line's dialect index.
pub const DIALECT_DOCUMENT: u32 = 0;

/// `door_statement::DIALECT_TARGET`: the HTTP+JSON line's dialect index.
pub const DIALECT_TARGET: u32 = 1;

/// `door_statement::DIALECT_FRAMED`: the framed (gRPC) line's dialect index.
pub const DIALECT_FRAMED: u32 = 2;

/// `door_statement::CLASS_BYTES_INDEX`: the bytes class's tail index.
pub const CLASS_BYTES_INDEX: u32 = 0;

/// `door_statement::CLASS_FEE_INDEX`: the fee unit's class's tail index.
pub const CLASS_FEE_INDEX: u32 = 1;

/// The crate root's `WELL_KNOWN_CARD_PATH`: the protocol's canonical card discovery path.
pub const WELL_KNOWN_CARD_PATH: &str = "/.well-known/agent-card.json";

/// The crate root's `MOUNT_PATH`: the plane's mount.
pub const MOUNT_PATH: &str = "/a2a";

/// The crate root's `ROUTE_MESSAGE_SEND`, under the mount.
pub const ROUTE_MESSAGE_SEND: &str = "/message:send";

/// The crate root's `ROUTE_TASKS`, under the mount.
pub const ROUTE_TASKS: &str = "/tasks";

/// The crate root's `ROUTE_TASK`, under the mount.
pub const ROUTE_TASK: &str = "/tasks/{id}";

/// `framed::SERVICE_PATH`: the gRPC service every rpc of the framed line is a method of.
pub const SERVICE_PATH: &str = "/lf.a2a.v1.A2AService";

/// `door_statement::NEED_OPEN_WEB`: the `NEEDS` index of the open-web need a push delivery rides.
pub const NEED_OPEN_WEB: u32 = 0;

/// `door_statement::NEED_AGENT`: the `NEEDS` index of the relayed calls to the registered agents.
pub const NEED_AGENT: u32 = 1;

/// `door_statement::NEED_GRPC`: the `NEEDS` index of the relayed calls to a gRPC-bound agent.
pub const NEED_GRPC: u32 = 2;

/// `claims::FRAMED_TRANSPORT`: the transport the framed binding is made against.
pub const FRAMED_TRANSPORT: &str = "grpc";

/// `door_statement::MEMBER_TARGET`: where a member need's target comes from.
pub const MEMBER_TARGET: &str = "settings.*.url";

/// `door_statement::CLIENT_IDENTITY_FROM`: where a member need's client identity comes from.
pub const CLIENT_IDENTITY_FROM: &str = "settings.*.client_identity";

/// `door_statement::PUSH_TRUST_FROM`: where the push need's trust anchor comes from.
pub const PUSH_TRUST_FROM: &str = "owned.agent_push.ca";

/// `records::HELD_KINDS`: the host-record kinds the door's tail states, in order.
pub const HELD_KINDS: &[&str] = &["task", "task_event", "push_config", "card", "card_approval"];

/// `door_statement::ROUTES` as `(verb, target)`, in order: a route's index is the claim an arrival
/// carries.
pub const ROUTES: &[(&str, &str)] = &[
    ("POST", "/a2a/message:send"),
    ("POST", "/a2a/message:stream"),
    ("GET", "/a2a/tasks"),
    ("GET", "/a2a/tasks/{id}"),
    ("POST", "/a2a/tasks/{id}"),
    ("POST", "/a2a/tasks/{id}/pushNotificationConfigs"),
    ("GET", "/a2a/tasks/{id}/pushNotificationConfigs"),
    ("GET", "/a2a/tasks/{id}/pushNotificationConfigs/{config_id}"),
    (
        "DELETE",
        "/a2a/tasks/{id}/pushNotificationConfigs/{config_id}",
    ),
    ("GET", "/a2a/extendedAgentCard"),
    ("GET", "/.well-known/oauth-protected-resource/a2a"),
    ("GET", "/.well-known/agent-card.json"),
    ("GET", "/a2a/agents/{agent_id}"),
    ("POST", "/a2a/agents/{agent_id}"),
    ("POST", "/a2a"),
    ("POST", "/a2a/"),
    ("POST", "/lf.a2a.v1.A2AService/{method}"),
];

/// The claim (route index) of `(verb, target)`.
///
/// # Panics
///
/// When the door states no such route.
#[must_use]
pub fn claim(verb: &str, target: &str) -> u32 {
    let i = ROUTES
        .iter()
        .position(|&(v, t)| v == verb && t == target)
        .unwrap_or_else(|| panic!("the door routes {verb} {target}"));
    u32::try_from(i).unwrap()
}
