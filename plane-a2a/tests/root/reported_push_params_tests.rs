// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! Push-config task identifiers through the actual root and public plane door.
use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn push_config_verbs_distinguish_malformed_task_ids_from_unheld_string_ids() {
    let _one = PUBLISHING.lock().await;
    let mut agent =
        Agent::start_answering(200, Arc::new(|r: &str| far_answer(r, "working", "working"))).await;
    agent.card.lock().unwrap()["capabilities"]["pushNotifications"] = serde_json::json!(true);
    let s = served(
        "reported-push-task-ids",
        &agent.entry("planner", "1h"),
        false,
        None,
    );
    approve(&s, "planner").await;
    let task = open_task(&s).await;
    // Discard the one legitimate task-opening request before checking local-only behavior.
    assert!(agent.relayed());
    for (method, alias) in [
        ("CreateTaskPushNotificationConfig", "task_id"),
        ("GetTaskPushNotificationConfig", "task_id"),
        ("ListTaskPushNotificationConfigs", "task_id"),
        ("DeleteTaskPushNotificationConfig", "task_id"),
        ("tasks/pushNotificationConfig/set", "id"),
        ("tasks/pushNotificationConfig/get", "id"),
        ("tasks/pushNotificationConfig/list", "id"),
        ("tasks/pushNotificationConfig/delete", "id"),
    ] {
        let mut cases = vec![serde_json::json!({})];
        for value in [
            serde_json::Value::Null,
            serde_json::json!(true),
            serde_json::json!(7),
            serde_json::json!([]),
            serde_json::json!({}),
        ] {
            cases.push(serde_json::json!({"taskId": value}));
        }
        // The first supplied member remains authoritative; a valid alias cannot hide null.
        let mut conflict = serde_json::json!({"taskId": null});
        conflict[alias] = serde_json::json!(task);
        cases.push(conflict);
        for params in cases {
            let (status, body) = document(
                &s,
                rpc("planner", method, &params.to_string(), Some(&s.token)),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{method} {params}: {body}");
            assert_eq!(body["error"]["code"], -32602, "{method} {params}: {body}");
            assert_eq!(body["id"], 1);
        }
        for name in ["taskId", alias] {
            // Empty strings preserve the existing not-found behavior; only type/presence changes.
            for value in ["", "not-a-held-task"] {
                let mut params = serde_json::json!({});
                params[name] = serde_json::json!(value);
                let (status, body) = document(
                    &s,
                    rpc("planner", method, &params.to_string(), Some(&s.token)),
                )
                .await;
                assert_eq!(status, StatusCode::NOT_FOUND, "{method} {params}: {body}");
                assert_eq!(body["error"]["code"], -32001, "{method} {params}: {body}");
            }
        }
    }
    // A real held task remains usable under each dialect's accepted alias.
    for (method, member) in [
        ("ListTaskPushNotificationConfigs", "task_id"),
        ("tasks/pushNotificationConfig/list", "id"),
    ] {
        let mut params = serde_json::json!({});
        params[member] = serde_json::json!(task);
        let (status, body) = document(
            &s,
            rpc("planner", method, &params.to_string(), Some(&s.token)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body.get("result").is_some(), "{body}");
    }
    assert!(
        !agent.relayed(),
        "malformed/local push verbs never reach the backend"
    );
}
