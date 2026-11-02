// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::Hop;

#[test]
fn a_task_hop_does_not_copy_its_envelope() {
    let parts: Vec<serde_json::Value> = (0..1000)
        .map(|i| serde_json::json!({ "kind": "text", "text": format!("part {i}") }))
        .collect();
    let envelope = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "message/send",
        "params": { "message": { "role": "user", "parts": parts } },
    });
    let parts = envelope["params"]["message"]["parts"].as_array().unwrap();
    let part_array = parts.as_ptr();
    let first_text = parts[0]["text"].as_str().unwrap().as_ptr();
    let last_text = parts[999]["text"].as_str().unwrap().as_ptr();
    let hop = Hop::task(serde_json::json!(1), "1.0", envelope);
    let held = hop.request.as_ref().expect("the task hop owns its request");
    let parts = held["params"]["message"]["parts"].as_array().unwrap();
    assert_eq!(parts.len(), 1000);
    assert_eq!(parts.as_ptr(), part_array);
    assert_eq!(parts[0]["text"].as_str().unwrap().as_ptr(), first_text);
    assert_eq!(parts[999]["text"].as_str().unwrap().as_ptr(), last_text);
    assert_eq!(parts[0]["text"], "part 0");
    assert_eq!(parts[999]["text"], "part 999");
}
