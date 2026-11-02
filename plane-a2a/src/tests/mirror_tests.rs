// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Busbar's own callback, mirrored onto the agent (the engine's `pushback`/`originate` cells).

use super::*;
use crate::local::{Dialect, LocalVerb};

#[test]
fn every_push_config_verb_mirrors_onto_its_v1_name_and_nothing_else_does() {
    for d in [Dialect::V10, Dialect::V03] {
        assert_eq!(
            mirrored_verb(LocalVerb::CreatePushConfig(d)),
            Some(method::CREATE_PUSH_CONFIG)
        );
        assert_eq!(
            mirrored_verb(LocalVerb::GetPushConfig(d)),
            Some(method::GET_PUSH_CONFIG)
        );
        assert_eq!(
            mirrored_verb(LocalVerb::ListPushConfigs(d)),
            Some(method::LIST_PUSH_CONFIGS)
        );
        assert_eq!(
            mirrored_verb(LocalVerb::DeletePushConfig(d)),
            Some(method::DELETE_PUSH_CONFIG)
        );
    }
    assert_eq!(mirrored_verb(LocalVerb::ListTasks), None);
    assert_eq!(mirrored_verb(LocalVerb::Subscribe), None);
}

#[test]
fn busbar_offers_only_an_https_callback_of_its_own() {
    assert_eq!(
        callback_url("https://gw.example/").as_deref(),
        Some("https://gw.example/a2a/push")
    );
    assert_eq!(callback_url("http://gw.example"), None);
    assert_eq!(callback_url("not a url"), None);
}

#[test]
fn the_params_name_busbars_registration_and_never_the_callers() {
    let create = create_params("b-1", "https://gw.example/a2a/push", "t.ab");
    assert_eq!(create["id"], "busbar-b-1");
    assert_eq!(create["taskId"], "b-1");
    assert_eq!(create["authentication"]["scheme"], "Bearer");
    assert_eq!(create["authentication"]["credentials"], "t.ab");
    assert_eq!(
        params_for(method::CREATE_PUSH_CONFIG, "b-1", &create),
        create
    );
    assert_eq!(
        params_for(method::LIST_PUSH_CONFIGS, "b-1", &create),
        serde_json::json!({ "taskId": "b-1" })
    );
    for m in [method::GET_PUSH_CONFIG, method::DELETE_PUSH_CONFIG] {
        assert_eq!(
            params_for(m, "b-1", &create),
            serde_json::json!({ "taskId": "b-1", "id": "busbar-b-1" })
        );
    }
}

#[test]
fn an_originated_request_is_framed_for_the_agents_binding() {
    let params = serde_json::json!({ "taskId": "b-1", "id": "busbar-b-1" });
    let rpc = request(
        Binding::JsonRpc,
        "https://agent.example/rpc?x=1",
        "1.0",
        method::GET_PUSH_CONFIG,
        &params,
    )
    .expect("framed");
    assert_eq!(rpc.method, b"POST");
    assert_eq!(rpc.target, b"/rpc?x=1");
    let doc: Value = serde_json::from_slice(&rpc.body).expect("JSON");
    assert_eq!(doc["id"], ORIGINATED_RPC_ID);
    assert_eq!(doc["method"], method::GET_PUSH_CONFIG);
    assert_eq!(doc["params"], params);
    let rest = request(
        Binding::HttpJson,
        "https://agent.example",
        "1.0",
        method::GET_PUSH_CONFIG,
        &params,
    )
    .expect("framed");
    assert_eq!(rest.method, b"GET");
    assert!(
        String::from_utf8_lossy(&rest.target).contains("b-1"),
        "{}",
        String::from_utf8_lossy(&rest.target)
    );
}

#[test]
fn a_read_that_does_not_find_busbars_registration_re_arms() {
    let found = serde_json::json!({ "jsonrpc": "2.0", "id": ORIGINATED_RPC_ID,
        "result": { "id": "busbar-b-1", "taskId": "b-1" } })
    .to_string();
    let gone = serde_json::json!({ "jsonrpc": "2.0", "id": ORIGINATED_RPC_ID,
        "result": { "configs": [] } })
    .to_string();
    let error = serde_json::json!({ "jsonrpc": "2.0", "id": ORIGINATED_RPC_ID,
        "error": { "code": -32001, "message": "no" } })
    .to_string();
    assert!(!drifted(
        Binding::JsonRpc,
        Some((200, found.as_bytes())),
        "busbar-b-1"
    ));
    assert!(drifted(
        Binding::JsonRpc,
        Some((200, gone.as_bytes())),
        "busbar-b-1"
    ));
    assert!(drifted(
        Binding::JsonRpc,
        Some((200, error.as_bytes())),
        "busbar-b-1"
    ));
    assert!(drifted(Binding::JsonRpc, Some((503, b"")), "busbar-b-1"));
    assert!(drifted(Binding::JsonRpc, None, "busbar-b-1"));
    assert!(!drifted(
        Binding::HttpJson,
        Some((200, br#"{"id":"busbar-b-1"}"#)),
        "busbar-b-1"
    ));

    let mut flight = Flight {
        stage: Stage::Mirror,
        method: method::GET_PUSH_CONFIG,
        backend_task: "b-1".into(),
        create: Value::Null,
        hop: hop(),
    };
    assert_eq!(flight.issuing(), method::GET_PUSH_CONFIG);
    flight.advance(Some((200, gone.as_bytes())));
    assert_eq!(flight.stage, Stage::Rearm);
    assert_eq!(flight.issuing(), method::CREATE_PUSH_CONFIG);
    flight.advance(None);
    assert_eq!(
        flight.stage,
        Stage::Done,
        "a failed re-arm is reported, never retried"
    );
    let mut create = Flight {
        stage: Stage::Mirror,
        method: method::CREATE_PUSH_CONFIG,
        backend_task: "b-1".into(),
        create: Value::Null,
        hop: hop(),
    };
    create.advance(None);
    assert_eq!(create.stage, Stage::Done, "only a read reconciles");
}

fn hop() -> Originated {
    Originated {
        agent: "planner".into(),
        url: "https://agent.example".into(),
        allow_private: false,
        binding: Binding::JsonRpc,
        version: "1.0",
        seq: 0,
        exchange: None,
    }
}

/// A listing moves only the rows busbar can match, by the state each reports strictly.
#[test]
fn a_listing_moves_only_what_busbar_can_match() {
    use crate::a2a::task::TaskState;
    let ours: std::collections::BTreeMap<String, String> =
        [("b-1".to_string(), "t-1".to_string())].into();
    let answer = serde_json::json!({ "jsonrpc": "2.0", "id": ORIGINATED_RPC_ID, "result": {
        "tasks": [
            { "id": "b-1", "status": { "state": "TASK_STATE_COMPLETED" } },
            { "id": "b-2", "status": { "state": "completed" } },
            { "id": "b-1", "status": { "state": "nonsense" } },
        ] } })
    .to_string();
    assert_eq!(
        listed_states(Binding::JsonRpc, Some((200, answer.as_bytes())), &ours),
        vec![("t-1".to_string(), TaskState::Completed)]
    );
    let bare = serde_json::json!({ "jsonrpc": "2.0", "id": ORIGINATED_RPC_ID,
        "result": [ { "id": "b-1", "status": { "state": "working" } } ] })
    .to_string();
    assert_eq!(
        listed_states(Binding::JsonRpc, Some((200, bare.as_bytes())), &ours).len(),
        1
    );
    assert!(listed_states(Binding::JsonRpc, Some((502, b"")), &ours).is_empty());
    assert!(listed_states(Binding::JsonRpc, None, &ours).is_empty());
}

/// BUSBAR'S OWN CALLBACK IS READ FROM `public_url` THE ONE WAY every published URL is

#[test]
fn busbars_callback_replaces_the_public_urls_path_as_every_published_url_does() {
    assert_eq!(
        callback_url("https://gw.example/busbar").as_deref(),
        Some("https://gw.example/a2a/push")
    );
    assert_eq!(
        callback_url("https://gw.example/?q=1").as_deref(),
        Some("https://gw.example/a2a/push")
    );
    assert_eq!(
        callback_url("https://gw.example/busbar").as_deref(),
        crate::a2a::public::absolute("https://gw.example/busbar", "/a2a/push").as_deref()
    );
}

/// A READ FINDS BUSBAR'S REGISTRATION BY ITS WHOLE `id`, never by a substring: `busbar-t10` is not

#[test]
fn a_read_names_busbars_config_by_its_whole_id() {
    let read = |result: Value| {
        serde_json::json!({ "jsonrpc": "2.0", "id": ORIGINATED_RPC_ID, "result": result })
            .to_string()
    };
    let drifted_on = |result: Value| {
        let body = read(result);
        drifted(Binding::JsonRpc, Some((200, body.as_bytes())), "busbar-t1")
    };
    assert!(
        drifted_on(serde_json::json!({ "id": "busbar-t10", "taskId": "t10" })),
        "another task's config is not busbar's"
    );
    assert!(
        drifted_on(serde_json::json!({ "configs": [ { "id": "busbar-t10" } ] })),
        "a listing of another task's config does not hold busbar's"
    );
    assert!(
        drifted_on(serde_json::json!({ "id": "theirs", "url": "https://x.test/busbar-t1" })),
        "a member that mentions the id is not the config"
    );
    assert!(!drifted_on(serde_json::json!({ "id": "busbar-t1" })));
    assert!(!drifted_on(
        serde_json::json!({ "configs": [ { "id": "other" }, { "id": "busbar-t1" } ] })
    ));
    assert!(!drifted_on(serde_json::json!([
        { "taskId": "t1", "pushNotificationConfig": { "id": "busbar-t1" } }
    ])));
    assert!(!drifted_on(
        serde_json::json!({ "taskId": "t1", "pushNotificationConfig": { "id": "busbar-t1" } })
    ));
}

#[test]
fn a_failed_v03_mirror_read_rearms_in_the_same_declared_dialect() {
    let mut flight = Flight {
        stage: Stage::Mirror,
        method: method::GET_PUSH_CONFIG,
        backend_task: "b-1".into(),
        create: create_params("b-1", "https://gw.example/a2a/push", "t.ab"),
        hop: hop(),
    };
    flight.hop.version = "0.3";
    let issued = |flight: &Flight| {
        let request = request(
            flight.hop.binding,
            &flight.hop.url,
            flight.hop.version,
            flight.issuing(),
            &flight.params(),
        )
        .expect("framed");
        serde_json::from_slice::<Value>(&request.body).unwrap()
    };
    assert_eq!(
        issued(&flight)["method"],
        "tasks/pushNotificationConfig/get"
    );
    let failed = json!({"jsonrpc":"2.0","id":ORIGINATED_RPC_ID,
        "error":{"code":-32601,"message":"not found"}})
    .to_string();
    flight.advance(Some((200, failed.as_bytes())));
    assert_eq!(flight.stage, Stage::Rearm);
    let rearm = issued(&flight);
    assert_eq!(rearm["method"], "tasks/pushNotificationConfig/set");
    assert_eq!(
        rearm["params"]["pushNotificationConfig"]["url"],
        "https://gw.example/a2a/push"
    );
    flight.advance(None);
    assert_eq!(
        flight.stage,
        Stage::Done,
        "an unanswered rearm does not loop"
    );
}

#[test]
fn mirror_debug_omits_the_callback_capability() {
    let flight = Flight {
        stage: Stage::Mirror,
        method: method::CREATE_PUSH_CONFIG,
        backend_task: "b-1".into(),
        create: create_params("b-1", "https://gw.example/a2a/push", "secret-capability"),
        hop: hop(),
    };
    let text = format!("{flight:?}");
    assert!(!text.contains("secret-capability"));
    assert!(!text.contains("authentication"));
    assert!(text.contains("Mirror"));
}

#[test]
fn cancelling_a_mirror_wipes_the_retained_rearm_capability() {
    const CREDENTIAL: &str = "callback-credential-custody-canary";
    crate::tests::request_custody_probe::assert_wiped(|| {
        drop(Flight {
            stage: Stage::Rearm,
            method: method::GET_PUSH_CONFIG,
            backend_task: "mirror-custody-task".into(),
            create: create_params(
                "mirror-custody-task",
                "https://callback.example",
                CREDENTIAL,
            ),
            hop: hop(),
        });
    });
}

#[test]
fn mirror_producer_trees_preserve_the_borrowed_capability_on_success_and_refusal() {
    const CREDENTIAL: &str = "callback-credential-custody-canary";
    let create = create_params(
        "mirror-custody-task",
        "https://callback.example",
        CREDENTIAL,
    );
    for version in ["0.3", crate::framed::DEFAULT_VERSION] {
        for url in ["https://agent.example/rpc", "not a url"] {
            crate::tests::request_custody_probe::assert_wiped(|| {
                let issued = request(
                    Binding::JsonRpc,
                    url,
                    version,
                    method::CREATE_PUSH_CONFIG,
                    &create,
                );
                if let Some(issued) = issued {
                    let body = String::from_utf8_lossy(&issued.body);
                    assert!(body.contains(CREDENTIAL));
                }
            });
            assert_eq!(create["authentication"]["credentials"], CREDENTIAL);
        }
    }
}
