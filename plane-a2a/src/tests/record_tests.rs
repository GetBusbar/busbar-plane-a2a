// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Round-trip tests for the A2A plane rows (`TaskRow` / `TaskEventRow`) through the store-seam

use super::*;

/// The task rows round-trip through serde unchanged. They cross a plugin ABI, so a field whose

#[test]
fn task_rows_round_trip_through_the_store_seam_encoding() {
    let task = TaskRow {
        task_id: "t-1".into(),
        context_id: "ctx-1".into(),
        principal: "key-1".into(),
        direction: "outbound".into(),
        state: "auth-required".into(),
        agent_id: "planner".into(),
        artifact_cursor: 7,
        push_callback: "https://caller.example/cb".into(),
        push_version: "0.3".into(),
        created_at: 10,
        updated_at: 20,
    };
    let body = serde_json::to_vec(&task).unwrap();
    assert_eq!(serde_json::from_slice::<TaskRow>(&body).unwrap(), task);
    let persisted = serde_json::json!({
        "task_id": "t-1", "context_id": "ctx-1", "principal": "key-1",
        "direction": "outbound", "state": "auth-required", "agent_id": "planner",
        "artifact_cursor": 7, "push_callback": "https://caller.example/cb",
        "push_version": "0.3", "created_at": 10, "updated_at": 20,
    });
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
        persisted
    );
    assert_eq!(serde_json::from_value::<TaskRow>(persisted).unwrap(), task);
}

#[test]
fn task_event_rows_round_trip_through_the_task_event_envelope() {
    let event = TaskEventRow {
        task_id: "t-1".into(),
        seq: 1,
        ts: 10,
        kind: "task.submitted".into(),
        context_id: "ctx-1".into(),
        principal: "key-1".into(),
        agent_id: String::new(),
        state: "submitted".into(),
        request_id: "req-1".into(),
        prev_hash: String::new(),
        hash: "deadbeef".into(),
        digest_version: DIGEST_VERSION_LEN_PREFIXED,
    };
    let body = serde_json::to_vec(&event).unwrap();
    assert_eq!(
        serde_json::from_slice::<TaskEventRow>(&body).unwrap(),
        event
    );
    let persisted = serde_json::json!({
        "task_id": "t-1", "seq": 1, "ts": 10, "kind": "task.submitted",
        "context_id": "ctx-1", "principal": "key-1", "agent_id": "",
        "state": "submitted", "request_id": "req-1", "prev_hash": "",
        "hash": "deadbeef", "digest_version": 2,
    });
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
        persisted
    );
    assert_eq!(
        serde_json::from_value::<TaskEventRow>(persisted).unwrap(),
        event
    );
}

#[test]
fn task_debug_does_not_reveal_a_callback_url_credential() {
    let task: TaskRow = serde_json::from_value(serde_json::json!({
        "task_id":"t", "context_id":"c", "principal":"caller", "direction":"outbound",
        "state":"working", "agent_id":"agent", "artifact_cursor":0,
        "push_callback":"https://receiver.example/cb?token=secret-webhook-token",
        "created_at":1, "updated_at":1
    }))
    .unwrap();
    assert!(!format!("{task:?}").contains("secret-webhook-token"));
    assert!(
        serde_json::to_string(&task)
            .unwrap()
            .contains("secret-webhook-token"),
        "the durable schema and bytes remain complete"
    );
}
