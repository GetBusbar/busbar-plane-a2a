// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

/// The real HTTP connector reports CUT when the peer closes before its declared body length.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cut_after_a_working_event_reports_an_error_and_fails_the_task() {
    let _one = PUBLISHING.lock().await;
    const WORKING: &str = "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"kind\":\"task\",\"id\":\"B1\",\"contextId\":\"BC\",\"status\":{\"state\":\"working\"}}}\n\n";
    for cut in [false, true] {
        let scenario = if cut { "relay-cut" } else { "relay-complete" };
        if !bootstrap::scenario(scenario, None).await {
            continue;
        }
        let event = if cut { WORKING } else { STREAMED };
        let agent = Agent::start_with(
            200,
            event,
            vec![
                ("content-type", EVENTS.to_string()),
                (
                    "content-length",
                    (event.len() + usize::from(cut)).to_string(),
                ),
            ],
            None,
        )
        .await;
        agent.streams();
        let instance = if cut {
            "relay-cut-after-event"
        } else {
            "relay-complete-event"
        };
        let s = served(instance, &agent.entry("planner", "1h"), false, None);
        approve(&s, "planner").await;
        let (status, body) = answered(
            &s.router,
            rpc("planner", "message/stream", STREAM, Some(&s.token)),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the first event committed the stream: {body}"
        );
        let events: Vec<serde_json::Value> = body
            .lines()
            .filter_map(|line| line.strip_prefix("data: "))
            .map(|data| serde_json::from_str(data).expect("a complete JSON event"))
            .collect();
        let first = events
            .first()
            .expect("the received task event remains visible");
        let task = first["result"]["id"]
            .as_str()
            .expect("busbar task identity");
        assert_ne!(task, "B1");
        if cut {
            assert_eq!(first["result"]["status"]["state"], "working");
            assert_eq!(events.last().unwrap()["error"]["code"], -32006, "{body}");
            assert!(!body.contains("127.0.0.1"), "{body}");
        } else {
            assert!(
                events.iter().all(|event| event.get("error").is_none()),
                "{body}"
            );
        }
        let (status, listed) =
            answered(&s.router, rpc("planner", "ListTasks", "{}", Some(&s.token))).await;
        assert_eq!(status, StatusCode::OK, "{listed}");
        let listed: serde_json::Value = serde_json::from_str(&listed).unwrap();
        let row = listed["result"]["tasks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["id"] == task)
            .expect("the stream's task remains in the caller's records");
        let state = row["status"]["state"]
            .as_str()
            .unwrap()
            .to_ascii_lowercase();
        assert!(
            state.contains(if cut { "failed" } else { "completed" }),
            "{row}"
        );
        bootstrap::scenario_finished(scenario);
    }
}
