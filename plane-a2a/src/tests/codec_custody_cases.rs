// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use prost::Message as _;
use serde_json::{json, Value};

use crate::tests::request_custody_probe::assert_wiped;

const SECRET: &str = "callback-credential-custody-canary";

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
    let message = crate::proto::pb::TaskPushNotificationConfig {
        task_id: "task".into(),
        id: "config".into(),
        url: "https://callback.example".into(),
        authentication: Some(crate::proto::pb::AuthenticationInfo {
            scheme: "Bearer".into(),
            credentials: SECRET.into(),
        }),
        ..Default::default()
    }
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
        assert_eq!(message.authentication.unwrap().credentials, SECRET);
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
        assert_eq!(config.authentication.unwrap().credentials, SECRET);
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
