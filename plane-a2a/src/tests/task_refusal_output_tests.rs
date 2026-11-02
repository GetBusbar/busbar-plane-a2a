// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Private refusal policy and error meaning; actual output windows run in unit_lifetime.

use super::*;

#[test]
fn refused_output_rejects_staged_writes_instead_of_discarding_them() {
    let mut pass = Pass::default();
    pass.served = true;
    pass.audit = Some(("agent:planner".into(), true));
    pass.response_only = true;
    let writes = [Write {
        kind: crate::records::KIND_TASK,
        key: "caller/task".into(),
        value: b"must not disappear".to_vec(),
    }];
    assert_eq!(
        check_response_effects(pass.response_only, &writes),
        Err(Outcome::Failed)
    );
}

#[test]
fn a_refused_delete_keeps_its_specific_error_and_caller_identity() {
    let answer = local::unrecorded_answer(
        LocalVerb::DeletePushConfig(local::Dialect::V10),
        &serde_json::json!(73),
    )
    .unwrap();
    assert_eq!(answer.status, 500);
    assert_eq!(
        serde_json::from_slice::<Value>(&answer.body).unwrap(),
        serde_json::json!({
            "jsonrpc":"2.0", "id":73, "error": {
                "code":-32603, "message":local::CONFIG_UNDELETED,
            },
        })
    );
    assert!(local::unrecorded_answer(LocalVerb::ListTasks, &Value::Null).is_none());
}
