// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The operation vocabulary: which method name is which priced operation.

use busbar_contract::ids::OpClassId;

/// Send one message to an agent and wait for the whole answer.
pub const OP_MESSAGE_SEND: OpClassId = OpClassId::new("message_send");

/// Send one message and receive the answer as a stream of events.
pub const OP_MESSAGE_STREAM: OpClassId = OpClassId::new("message_stream");

/// Read one task back.
pub const OP_TASK_GET: OpClassId = OpClassId::new("task_get");

/// List the tasks this caller may see.
pub const OP_TASK_LIST: OpClassId = OpClassId::new("task_list");

/// Ask for one task to stop.
pub const OP_TASK_CANCEL: OpClassId = OpClassId::new("task_cancel");

/// Re-attach to a task's event stream.
pub const OP_TASK_SUBSCRIBE: OpClassId = OpClassId::new("task_subscribe");

/// Create a push-notification configuration for a task.
pub const OP_PUSH_CONFIG_CREATE: OpClassId = OpClassId::new("push_config_create");

/// Read a push-notification configuration back.
pub const OP_PUSH_CONFIG_GET: OpClassId = OpClassId::new("push_config_get");

/// List a task's push-notification configurations.
pub const OP_PUSH_CONFIG_LIST: OpClassId = OpClassId::new("push_config_list");

/// Delete a push-notification configuration.
pub const OP_PUSH_CONFIG_DELETE: OpClassId = OpClassId::new("push_config_delete");

/// Read the extended agent card, which only an authenticated caller may see.
pub const OP_AGENT_CARD: OpClassId = OpClassId::new("agent_card");

/// One push event arriving from an agent this node dialled.
pub const OP_PUSH_EVENT: OpClassId = OpClassId::new("push_event");

/// Every operation class this plane's units can be, in declaration order.
pub const OP_CLASSES: &[OpClassId] = &[
    OP_MESSAGE_SEND,
    OP_MESSAGE_STREAM,
    OP_TASK_GET,
    OP_TASK_LIST,
    OP_TASK_CANCEL,
    OP_TASK_SUBSCRIBE,
    OP_PUSH_CONFIG_CREATE,
    OP_PUSH_CONFIG_GET,
    OP_PUSH_CONFIG_LIST,
    OP_PUSH_CONFIG_DELETE,
    OP_AGENT_CARD,
    OP_PUSH_EVENT,
];

/// Which spelling of the vocabulary a request used.
///
/// Carried as a fact, never as a class: see the module note on why the spelling does not change the
/// price.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Wording {
    /// The slash-separated lower-case wording of the earlier revision.
    Slashed,
    /// The title-case verb wording of the later revision.
    Verb,
}

/// One row of the vocabulary: a method name, how it is spelled, and what it costs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MethodRow {
    /// The method name exactly as it appears on the wire.
    pub method: &'static str,
    /// Which of the two spellings it is.
    pub wording: Wording,
    /// Which operation class a unit carrying it is.
    pub op: OpClassId,
    /// Whether the answer arrives as a stream of events rather than as one reply.
    pub multi_frame: bool,
}

/// Every method name this plane reads, in the order the vocabulary tables list them.
pub const METHODS: &[MethodRow] = &[
    MethodRow {
        method: "message/send",
        wording: Wording::Slashed,
        op: OP_MESSAGE_SEND,
        multi_frame: false,
    },
    MethodRow {
        method: "SendMessage",
        wording: Wording::Verb,
        op: OP_MESSAGE_SEND,
        multi_frame: false,
    },
    MethodRow {
        method: "message/stream",
        wording: Wording::Slashed,
        op: OP_MESSAGE_STREAM,
        multi_frame: true,
    },
    MethodRow {
        method: "SendStreamingMessage",
        wording: Wording::Verb,
        op: OP_MESSAGE_STREAM,
        multi_frame: true,
    },
    MethodRow {
        method: "tasks/get",
        wording: Wording::Slashed,
        op: OP_TASK_GET,
        multi_frame: false,
    },
    MethodRow {
        method: "GetTask",
        wording: Wording::Verb,
        op: OP_TASK_GET,
        multi_frame: false,
    },
    MethodRow {
        method: "tasks/list",
        wording: Wording::Slashed,
        op: OP_TASK_LIST,
        multi_frame: false,
    },
    MethodRow {
        method: "ListTasks",
        wording: Wording::Verb,
        op: OP_TASK_LIST,
        multi_frame: false,
    },
    MethodRow {
        method: "tasks/cancel",
        wording: Wording::Slashed,
        op: OP_TASK_CANCEL,
        multi_frame: false,
    },
    MethodRow {
        method: "CancelTask",
        wording: Wording::Verb,
        op: OP_TASK_CANCEL,
        multi_frame: false,
    },
    MethodRow {
        method: "tasks/resubscribe",
        wording: Wording::Slashed,
        op: OP_TASK_SUBSCRIBE,
        multi_frame: true,
    },
    MethodRow {
        method: "SubscribeToTask",
        wording: Wording::Verb,
        op: OP_TASK_SUBSCRIBE,
        multi_frame: true,
    },
    MethodRow {
        method: "tasks/pushNotificationConfig/set",
        wording: Wording::Slashed,
        op: OP_PUSH_CONFIG_CREATE,
        multi_frame: false,
    },
    MethodRow {
        method: "CreateTaskPushNotificationConfig",
        wording: Wording::Verb,
        op: OP_PUSH_CONFIG_CREATE,
        multi_frame: false,
    },
    MethodRow {
        method: "tasks/pushNotificationConfig/get",
        wording: Wording::Slashed,
        op: OP_PUSH_CONFIG_GET,
        multi_frame: false,
    },
    MethodRow {
        method: "GetTaskPushNotificationConfig",
        wording: Wording::Verb,
        op: OP_PUSH_CONFIG_GET,
        multi_frame: false,
    },
    MethodRow {
        method: "tasks/pushNotificationConfig/list",
        wording: Wording::Slashed,
        op: OP_PUSH_CONFIG_LIST,
        multi_frame: false,
    },
    MethodRow {
        method: "ListTaskPushNotificationConfigs",
        wording: Wording::Verb,
        op: OP_PUSH_CONFIG_LIST,
        multi_frame: false,
    },
    MethodRow {
        method: "tasks/pushNotificationConfig/delete",
        wording: Wording::Slashed,
        op: OP_PUSH_CONFIG_DELETE,
        multi_frame: false,
    },
    MethodRow {
        method: "DeleteTaskPushNotificationConfig",
        wording: Wording::Verb,
        op: OP_PUSH_CONFIG_DELETE,
        multi_frame: false,
    },
    MethodRow {
        method: "agent/getAuthenticatedExtendedCard",
        wording: Wording::Slashed,
        op: OP_AGENT_CARD,
        multi_frame: false,
    },
    MethodRow {
        method: "GetExtendedAgentCard",
        wording: Wording::Verb,
        op: OP_AGENT_CARD,
        multi_frame: false,
    },
];

/// The row for one method name, if this plane carries that method at all.
#[must_use]
pub fn row_for(method: &str) -> Option<&'static MethodRow> {
    METHODS.iter().find(|r| r.method == method)
}

/// The suffix a method the vocabulary does not list reads as a stream by: such a method is
pub const STREAM_SUFFIX: &str = "/stream";

/// The class a method is relayed as: its row's, or for a method the vocabulary does not list, the
#[must_use]
pub fn relay_class(method: &str) -> OpClassId {
    match row_for(method) {
        Some(row) => row.op,
        None if method.ends_with(STREAM_SUFFIX) => OP_MESSAGE_STREAM,
        None => OP_MESSAGE_SEND,
    }
}

#[cfg(test)]
#[path = "tests/ops.rs"]
mod tests;
