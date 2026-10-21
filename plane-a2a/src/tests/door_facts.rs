// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DOOR-DRIVEN TESTS' FACTS ARE THE DOOR'S. `tests/unit_lifetime.rs`,
//! `tests/project_session.rs` and the plugin crate's `plane-a2a-plugin/tests/both_ways.rs` reach the plane only through `door` (the crate's one public item, and
//! its root keeps the literal `#![forbid(unsafe_code)]`, so the raw door table they drive is read in
//! those test crates, not here). The private constants they need are restated in
//! `tests/support/door_facts.rs`; this test includes that same file and holds each value to the item
//! it restates.

#[path = "../../tests/support/door_facts.rs"]
#[allow(dead_code)] // `claim` is the door-driven tests' reader, not this check's
mod stated;

#[test]
fn the_door_driven_tests_restate_the_doors_own_constants() {
    assert_eq!(stated::MAX_UNITS, crate::agent_door::MAX_UNITS);
    assert_eq!(
        stated::DIALECT_DOCUMENT,
        crate::door_statement::DIALECT_DOCUMENT
    );
    assert_eq!(
        stated::CLASS_BYTES_INDEX,
        crate::door_statement::CLASS_BYTES_INDEX
    );
    assert_eq!(
        stated::CLASS_FEE_INDEX,
        crate::door_statement::CLASS_FEE_INDEX
    );
    assert_eq!(stated::WELL_KNOWN_CARD_PATH, crate::WELL_KNOWN_CARD_PATH);
    assert_eq!(
        stated::DIALECT_TARGET,
        crate::door_statement::DIALECT_TARGET
    );
    assert_eq!(
        stated::DIALECT_FRAMED,
        crate::door_statement::DIALECT_FRAMED
    );
    assert_eq!(stated::MOUNT_PATH, crate::MOUNT_PATH);
    assert_eq!(stated::ROUTE_MESSAGE_SEND, crate::ROUTE_MESSAGE_SEND);
    assert_eq!(stated::ROUTE_TASKS, crate::ROUTE_TASKS);
    assert_eq!(stated::ROUTE_TASK, crate::ROUTE_TASK);
    assert_eq!(stated::SERVICE_PATH, crate::framed::SERVICE_PATH);
    assert_eq!(stated::NEED_OPEN_WEB, crate::door_statement::NEED_OPEN_WEB);
    assert_eq!(stated::NEED_AGENT, crate::door_statement::NEED_AGENT);
    assert_eq!(stated::NEED_GRPC, crate::door_statement::NEED_GRPC);
    assert_eq!(stated::FRAMED_TRANSPORT, crate::claims::FRAMED_TRANSPORT);
    assert_eq!(stated::MEMBER_TARGET, crate::door_statement::MEMBER_TARGET);
    assert_eq!(
        stated::CLIENT_IDENTITY_FROM,
        crate::door_statement::CLIENT_IDENTITY_FROM
    );
    assert_eq!(
        stated::PUSH_TRUST_FROM,
        crate::door_statement::PUSH_TRUST_FROM
    );
    assert_eq!(stated::HELD_KINDS, crate::records::HELD_KINDS);
    let routes: Vec<(&str, &str)> = crate::door_statement::ROUTES
        .iter()
        .map(|r| (r.verb, r.target))
        .collect();
    assert_eq!(stated::ROUTES, &routes[..]);
}

#[path = "../../tests/support/root_facts.rs"]
#[allow(dead_code)] // the root leg's reader, each item held by a check below
mod root_stated;

/// THE ROOT LEG'S RESTATED FACTS ARE THE DOOR'S OWN: each constant `tests/root/mod.rs` names is
/// equal to the private item it restates.
#[test]
fn the_root_leg_restates_the_doors_own_constants() {
    use crate::door_statement as ds;
    assert_eq!(root_stated::PUSH_SECTION, ds::PUSH_SECTION);
    assert_eq!(root_stated::PUSH_CA_KEY, ds::PUSH_CA_KEY);
    assert_eq!(root_stated::PUSH_TRUST_FROM, ds::PUSH_TRUST_FROM);
    assert_eq!(root_stated::NEED_AGENT, ds::NEED_AGENT);
    assert_eq!(root_stated::NEED_GRPC, ds::NEED_GRPC);
    assert_eq!(root_stated::SERVICE_NAME, crate::proto::SERVICE_NAME);
    assert_eq!(
        root_stated::FRAMED_TRANSPORT,
        crate::claims::FRAMED_TRANSPORT
    );
    assert_eq!(root_stated::ROLE_USER, crate::proto::pb::Role::User as u64);
    assert_eq!(
        root_stated::TASK_STATE_WORKING,
        crate::proto::pb::TaskState::Working as u64
    );
}

/// THE ROOT LEG'S PROTOBUF WORDS ARE THE GENERATED MESSAGES': the requests it writes decode, as the
/// generated messages, to what the plane's own encoder writes for the same params, and the readers
/// it holds the far end's bytes to read what the plane's encoder wrote and what the generated
/// response encodes.
#[test]
fn the_root_leg_writes_and_reads_the_generated_messages() {
    use crate::framed::{request_message, Rpc};
    use crate::proto::pb;
    use prost::Message as _;

    let params = serde_json::json!({ "message": {
        "messageId": "m-1", "role": "ROLE_USER", "parts": [{ "text": "PLAN THE MIGRATION" }] } });
    let planes = request_message(Rpc::SendMessage, &params).expect("a SendMessageRequest");
    let stated = root_stated::send_message_request("m-1", "PLAN THE MIGRATION");
    assert_eq!(
        pb::SendMessageRequest::decode(&stated[..]).expect("the stated bytes decode"),
        pb::SendMessageRequest::decode(&planes[..]).expect("the plane's bytes decode"),
    );
    for bytes in [&stated, &planes] {
        assert_eq!(
            root_stated::read_send_message_request(bytes).expect("the stated reader reads it"),
            root_stated::SentMessage {
                message_id: "m-1".into(),
                role: root_stated::ROLE_USER,
                texts: vec!["PLAN THE MIGRATION".into()],
            }
        );
    }

    let params = serde_json::json!({ "id": "no-such-task" });
    let planes = request_message(Rpc::GetTask, &params).expect("a GetTaskRequest");
    let stated = root_stated::get_task_request("no-such-task");
    assert_eq!(
        pb::GetTaskRequest::decode(&stated[..]).expect("the stated bytes decode"),
        pb::GetTaskRequest::decode(&planes[..]).expect("the plane's bytes decode"),
    );

    let response: pb::SendMessageResponse = serde_json::from_value(serde_json::json!({
        "task": { "id": "far-task", "status": { "state": "TASK_STATE_WORKING" } }
    }))
    .expect("a SendMessageResponse");
    assert_eq!(
        root_stated::send_message_response_task_state(&response.encode_to_vec())
            .expect("the stated reader reads it"),
        root_stated::TASK_STATE_WORKING
    );
}
