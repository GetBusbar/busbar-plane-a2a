// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use prost::Message as _;
use serde_json::{json, Value};

use crate::tests::request_custody_probe::assert_wiped;

const SECRET: &str = "callback-credential-custody-canary";

#[test]
fn outbound_http_json_retires_its_cloned_credentials_on_success_and_every_refusal() {
    let send = json!({"message":{"messageId":"m"}, "configuration":{
        "pushNotificationConfig":{"authentication":{"credentials":SECRET}}
    }});
    let invalid_tenant = json!({"tenant":"..", "privateExtension":SECRET});
    let missing_path = json!({"privateExtension":SECRET});
    let invalid_path = json!({"id":false, "privateExtension":SECRET});
    let unsupported_get = json!({"id":"t", "privateExtension":SECRET});
    for (method, params, succeeds) in [
        ("SendMessage", &send, true),
        ("SendMessage", &invalid_tenant, false),
        ("GetTask", &missing_path, false),
        ("GetTask", &invalid_path, false),
        ("GetTask", &unsupported_get, false),
    ] {
        assert_wiped(|| {
            let framed = crate::binding::compose("https://agent.example", method, params);
            assert_eq!(framed.is_ok(), succeeds);
            if let Ok(framed) = framed {
                let body: Value = serde_json::from_slice(&framed.body).unwrap();
                assert_eq!(
                    body["configuration"]["pushNotificationConfig"]["authentication"]
                        ["credentials"],
                    SECRET
                );
            }
        });
    }
    assert_eq!(
        send["configuration"]["pushNotificationConfig"]["authentication"]["credentials"],
        SECRET
    );
}

#[test]
fn outbound_http_json_body_has_custody_until_transfer_or_abandonment() {
    let secret = std::str::from_utf8(crate::tests::raw_custody_probe::SECRET).unwrap();
    let params = json!({"message":{"messageId":"m"},"credential":secret});
    crate::tests::raw_custody_probe::assert_wiped(|| {
        let framed =
            crate::binding::compose("https://agent.example", "SendMessage", &params).unwrap();
        assert!(framed
            .body
            .windows(secret.len())
            .any(|part| part == secret.as_bytes()));
        drop(framed);
    });
    crate::tests::raw_custody_probe::assert_wiped(|| {
        assert!(std::panic::catch_unwind(|| {
            let _framed =
                crate::binding::compose("https://agent.example", "SendMessage", &params).unwrap();
            panic!("injected caller unwind");
        })
        .is_err());
    });
}

#[test]
fn rest_body_copies_wipe_their_initialized_credentials_and_keep_path_precedence() {
    let body = serde_json::to_vec(&json!({"taskId":"body-task", "task_id":SECRET,
        "url":"https://callback.example", "authentication":{"scheme":"Bearer", "credentials":SECRET}})).unwrap();
    let route = crate::statement::ROUTES
        .iter()
        .find(|route| {
            route.verb == "POST" && route.target == "/a2a/tasks/{id}/pushNotificationConfigs"
        })
        .unwrap();
    assert_wiped(|| {
        let bytes =
            crate::rest::compose(route, "/a2a/tasks/path-task/pushNotificationConfigs", &body)
                .unwrap()
                .unwrap();
        let request: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(request["params"]["taskId"], "path-task");
        assert!(request["params"].get("task_id").is_none());
        assert_eq!(request["params"]["authentication"]["credentials"], SECRET);
    });
}

#[test]
fn rest_replaced_params_wipe_before_the_replacement_is_retained() {
    assert_wiped(|| {
        let params = crate::rest::Params::new()
            .set("authentication", json!({"credentials":SECRET}))
            .merge(&json!({"authentication":{"scheme":"None"}}));
        let value = params.into_value();
        assert_eq!(value, json!({"authentication":{"scheme":"None"}}));
    });
    assert_wiped(|| drop(crate::rest::Params::new().set("credentials", SECRET)));
}

#[test]
fn framed_composed_json_wipes_its_initialized_credentials_after_serialization() {
    let message =
        crate::proto::custody::initialized::<crate::proto::pb::TaskPushNotificationConfig>(
            |__custody_message| {
                __custody_message.task_id = "task".into();
                __custody_message.id = "config".into();
                __custody_message.url = "https://callback.example".into();
                __custody_message.authentication = Some(crate::proto::pb::AuthenticationInfo {
                    scheme: "Bearer".into(),
                    credentials: SECRET.into(),
                });
            },
        )
        .encode_to_vec();
    assert_wiped(|| {
        let composed = crate::framed::compose(
            crate::framed::Rpc::CreateTaskPushNotificationConfig,
            &message,
        )
        .unwrap();
        let request: Value = serde_json::from_slice(&composed).unwrap();
        assert_eq!(request["params"]["authentication"]["credentials"], SECRET);
    });
}

#[test]
fn framed_answer_dom_wipes_credentials_after_transcoding() {
    let body = serde_json::to_vec(&json!({"jsonrpc":"2.0", "id":7, "result":{
        "taskId":"task", "id":"config", "url":"https://callback.example",
        "authentication":{"scheme":"Bearer", "credentials":SECRET}
    }}))
    .unwrap();
    assert_wiped(|| {
        let bytes = crate::framed::answer_message(
            crate::framed::Rpc::GetTaskPushNotificationConfig,
            200,
            &body,
        )
        .unwrap();
        let message =
            crate::proto::pb::TaskPushNotificationConfig::decode(bytes.as_slice()).unwrap();
        assert_eq!(message.authentication.as_ref().unwrap().credentials, SECRET);
    });
}

#[test]
fn framed_answer_dom_is_wiped_when_typed_conversion_refuses_the_answer() {
    let body = serde_json::to_vec(&json!({"jsonrpc":"2.0", "id":7, "result":{
        "authentication":{"scheme":"Bearer", "credentials":SECRET}, "unknownMember":true
    }}))
    .unwrap();
    assert_wiped(|| {
        assert!(crate::framed::answer_message(
            crate::framed::Rpc::GetTaskPushNotificationConfig,
            200,
            &body
        )
        .is_err());
    });
}

#[test]
fn framed_message_id_replacement_wipes_the_old_owned_string_and_preserves_the_borrowed_request() {
    let original = json!({"params":{"message":{"messageId":SECRET, "role":"ROLE_USER"}}});
    assert_wiped(|| {
        let replaced = crate::framed::with_message_id(&original, "new-message");
        assert_eq!(replaced["params"]["message"]["messageId"], "new-message");
        assert_eq!(original["params"]["message"]["messageId"], SECRET);
    });
}

#[test]
fn borrowing_protojson_params_preserves_aliases_errors_and_the_callers_owner() {
    for task_name in ["taskId", "task_id"] {
        let mut params = json!({"id":"config", "url":"https://callback.example",
            "authentication":{"scheme":"Bearer", "credentials":SECRET}});
        params[task_name] = json!("task");
        let expected = params.clone();
        let bytes = crate::framed::request_message(
            crate::framed::Rpc::CreateTaskPushNotificationConfig,
            &params,
        )
        .unwrap();
        let config =
            crate::proto::pb::TaskPushNotificationConfig::decode(bytes.as_slice()).unwrap();
        assert_eq!(config.task_id, "task");
        assert_eq!(config.authentication.as_ref().unwrap().credentials, SECRET);
        assert_eq!(params, expected, "the existing borrowed owner is untouched");
        params["tenant"] = json!(false);
        assert!(crate::framed::request_message(
            crate::framed::Rpc::CreateTaskPushNotificationConfig,
            &params
        )
        .is_err());
        assert_eq!(params["authentication"]["credentials"], SECRET);
    }
}
