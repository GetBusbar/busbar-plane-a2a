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

    assert!(
        !agent.relayed(),
        "malformed and unheld push verbs never reach the backend"
    );
    let mut valid_answers = Vec::new();
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
        valid_answers.push(body.to_string());
    }
    let mirrored = heard(&mut agent);
    assert_eq!(
        mirrored.len(),
        4,
        "each valid list mirrors and re-arms once"
    );
    for pair in mirrored.chunks_exact(2) {
        let documents: Vec<serde_json::Value> = pair
            .iter()
            .map(|request| {
                assert!(
                    !request.contains(&s.token),
                    "the caller credential stays local"
                );
                serde_json::from_str(request.split_once("\r\n\r\n").unwrap().1)
                    .expect("a mirrored JSON-RPC request")
            })
            .collect();
        for document in &documents {
            assert_eq!(document["jsonrpc"], "2.0");
            assert_eq!(document["id"], "busbar-originated");
        }
        assert_eq!(documents[0]["method"], "tasks/pushNotificationConfig/list");
        assert_eq!(documents[0]["params"], serde_json::json!({"id": FAR_TASK}));
        assert_eq!(documents[1]["method"], "tasks/pushNotificationConfig/set");
        assert_eq!(documents[1]["params"]["taskId"], FAR_TASK);
        let config = &documents[1]["params"]["pushNotificationConfig"];
        assert_eq!(config["id"], format!("busbar-{FAR_TASK}"));
        assert_eq!(config["url"], format!("https://gw.example{}/push", mount()));
        assert_eq!(
            config["authentication"]["schemes"],
            serde_json::json!(["Bearer"])
        );
        let capability = config["authentication"]["credentials"]
            .as_str()
            .filter(|value| !value.is_empty())
            .expect("busbar registers its own callback capability");
        assert_ne!(capability, s.token);
        for answer in &valid_answers {
            assert!(
                !answer.contains(capability),
                "the callback capability stays private"
            );
            assert!(
                !answer.contains(FAR_TASK),
                "the backend task id stays private"
            );
            assert!(
                !answer.contains("https://gw.example"),
                "the callback stays private"
            );
        }
    }
}
