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
