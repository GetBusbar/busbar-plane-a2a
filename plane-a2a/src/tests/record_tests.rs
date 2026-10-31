// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Round-trip tests for the A2A plane rows (`TaskRow` / `TaskEventRow`) through the store-seam
//! `PlaneRecord` encoding — field-name stability across the plugin ABI and terminal-state
//! disposition. Relocated out of `record.rs` per the tests-in-their-own-file convention.

use super::*;

/// The task rows round-trip through serde unchanged. They cross a plugin ABI, so a field whose
/// serialized name drifts is a field a backend silently stops persisting. (Moved here from
/// `busbar-api` in the 1.7.0 plane extraction — the plane owns its own row schema now.)
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
    // THE EXACT WIRE, every field by name and in order (`push_version` included): a rename of any
    // field changes these bytes, and a persisted row in this shape must still load.
    let wire = r#"{"task_id":"t-1","context_id":"ctx-1","principal":"key-1","direction":"outbound","state":"auth-required","agent_id":"planner","artifact_cursor":7,"push_callback":"https://caller.example/cb","push_version":"0.3","created_at":10,"updated_at":20}"#;
    assert_eq!(String::from_utf8(body).unwrap(), wire);
    assert_eq!(serde_json::from_str::<TaskRow>(wire).unwrap(), task);
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
    // THE EXACT WIRE, as for the task row: a rename of `seq`, `prev_hash`, `digest_version` or any
    // other field changes these bytes, and a persisted event in this shape must still load.
    let wire = r#"{"task_id":"t-1","seq":1,"ts":10,"kind":"task.submitted","context_id":"ctx-1","principal":"key-1","agent_id":"","state":"submitted","request_id":"req-1","prev_hash":"","hash":"deadbeef","digest_version":2}"#;
    assert_eq!(String::from_utf8(body).unwrap(), wire);
    assert_eq!(serde_json::from_str::<TaskEventRow>(wire).unwrap(), event);
}
