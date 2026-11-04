// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[test]
fn delete_of_a_different_config_refuses_without_disarming_the_held_callback() {
    for (create, delete, get, create_params, address) in [
        (
            "CreateTaskPushNotificationConfig",
            "DeleteTaskPushNotificationConfig",
            "GetTaskPushNotificationConfig",
            json!({"taskId":"t1", "id":"kept", "url":"https://callback.example/notify"}),
            json!({"taskId":"t1", "id":"kept"}),
        ),
        (
            "tasks/pushNotificationConfig/set",
            "tasks/pushNotificationConfig/delete",
            "tasks/pushNotificationConfig/get",
            json!({"taskId":"t1", "pushNotificationConfig":{"id":"kept", "url":"https://callback.example/notify"}}),
            json!({"taskId":"t1", "pushNotificationConfigId":"kept"}),
        ),
    ] {
        let mut desk = desk();
        assert_eq!(call(&mut desk, create, create_params, ALICE).0, 200);
        let held = desk
            .book
            .get(KIND_PUSH_CONFIG, &task_key(ALICE, "t1"))
            .unwrap();
        let member = if delete.contains('/') {
            "pushNotificationConfigId"
        } else {
            "id"
        };
        for value in [Some(json!("different")), None] {
            let mut params = json!({"taskId":"t1"});
            if let Some(value) = value {
                params[member] = value;
            }
            let (status, body) = call(&mut desk, delete, params, ALICE);
            assert_eq!(status, 404, "{delete}: {body}");
            assert_eq!(body["error"]["code"], TASK_NOT_FOUND);
            assert_eq!(body["id"], 7);
            assert_eq!(
                desk.book
                    .get(KIND_PUSH_CONFIG, &task_key(ALICE, "t1"))
                    .unwrap(),
                held
            );
            assert_eq!(call(&mut desk, get, address.clone(), ALICE).0, 200);
        }
        for _ in 0..2 {
            let (status, body) = call(&mut desk, delete, address.clone(), ALICE);
            assert_eq!(status, 200, "matching and repeated delete: {body}");
            assert!(body.get("result").is_some());
        }
        assert!(desk
            .book
            .get(KIND_PUSH_CONFIG, &task_key(ALICE, "t1"))
            .unwrap()
            .is_none());
    }
}

#[test]
fn malformed_push_records_fail_instead_of_appearing_absent() {
    assert!(decode_config(b"not json").is_err());
}

#[test]
fn auth_scheme_requires_http_token_and_controls_are_not_trimmed_away() {
    for scheme in ["Bearer/", "Basic:", "a(b)", "a=b", "a@b"] {
        assert!(
            delivery_auth(&json!({"authentication":{"scheme":scheme,"credentials":"secret"}}))
                .is_err()
        );
    }
    assert!(delivery_auth(
        &json!({"authentication":{"scheme":"Bearer","credentials":"secret\r\n"}})
    )
    .is_err());
}

#[test]
fn absent_config_id_is_addressable_and_empty_token_is_absent() {
    let mut desk = desk();
    let (status, body) = call(
        &mut desk,
        "CreateTaskPushNotificationConfig",
        json!({"taskId":"t1","url":"https://callback.example/notify","token":""}),
        ALICE,
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["result"]["id"], "t1");
    assert_eq!(
        call(
            &mut desk,
            "GetTaskPushNotificationConfig",
            json!({"taskId":"t1","id":"t1"}),
            ALICE
        )
        .0,
        200
    );
}

#[test]
fn invalid_page_sizes_are_refused() {
    for size in [json!(-1), json!(1.5), json!("no"), json!(true)] {
        let (status, body) = call(&mut desk(), "ListTasks", json!({"pageSize":size}), ALICE);
        assert_eq!(status, 400, "{body}");
        assert_eq!(body["error"]["code"], INVALID_PARAMS);
    }
}

#[test]
fn local_debug_never_formats_response_or_callback_secrets() {
    let answer = LocalAnswer {
        status: 200,
        body: b"answer-secret".to_vec(),
    };
    assert!(!format!("{answer:?}").contains("answer-secret"));
    let config = PushConfig {
        id: "id".into(),
        url: "https://example.test/?secret".into(),
        authentication: None,
        version: "1.0".into(),
    };
    assert!(!format!("{config:?}").contains("secret"));
}

#[test]
fn corrupt_durable_config_cannot_be_read_or_deleted_as_absent() {
    for method in [
        "GetTaskPushNotificationConfig",
        "DeleteTaskPushNotificationConfig",
        "CreateTaskPushNotificationConfig",
    ] {
        let mut desk = desk();
        desk.book.apply(&[Write {
            kind: KIND_PUSH_CONFIG,
            key: task_key(ALICE, "t1"),
            value: b"not-json".to_vec(),
        }]);
        let request = json!({"id":1,"params":{"taskId":"t1","id":"cfg","url":"https://example.test/callback"}});
        assert!(matches!(
            answer_local(
                &mut desk,
                verb_of(method).unwrap(),
                &request,
                ALICE,
                300,
                &mut Vec::new()
            ),
            Err(Halt::Failed(_))
        ));
        assert_eq!(
            desk.book
                .value(KIND_PUSH_CONFIG, &task_key(ALICE, "t1"))
                .unwrap(),
            b"not-json"
        );
    }
}

#[test]
fn malformed_task_is_neither_missing_nor_silently_omitted() {
    for method in ["ListTasks", "GetTaskPushNotificationConfig"] {
        let mut desk = desk();
        let mut held = tasks::get(&mut desk.book, ALICE, "t1", 300)
            .unwrap()
            .unwrap();
        held.row.state = "invalid-state".into();
        desk.book.hold(ALICE, &held);
        let request = json!({"id":1,"params":{"taskId":"t1","id":"cfg"}});
        assert!(matches!(
            answer_local(
                &mut desk,
                verb_of(method).unwrap(),
                &request,
                ALICE,
                300,
                &mut Vec::new()
            ),
            Err(Halt::Failed(_))
        ));
    }
}
