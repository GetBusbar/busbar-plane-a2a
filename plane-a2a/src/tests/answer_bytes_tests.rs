// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The byte splice of a far end's answer: busbar's identity at the members' own spans, every other
//! byte as the far end wrote it, and the same identity the value path gives.

use serde_json::{json, Value};

use super::*;

const WRAPPERS: [(&str, &str); 4] = [
    ("task", "id"),
    ("message", "taskId"),
    ("statusUpdate", "taskId"),
    ("artifactUpdate", "taskId"),
];

fn spliced(result: &str, skill: Option<&str>) -> String {
    let out = rewrite_identity(
        result.as_bytes(),
        &WRAPPERS,
        "T",
        "C",
        skill.map(|s| ("busbar/skill", s)),
    )
    .expect("an object");
    String::from_utf8(out).unwrap()
}

/// The value path's answer for the same result (`task_identity::rewrite_identity`).
fn valued(result: &str, skill: Option<&str>) -> Value {
    let mut v: Value = serde_json::from_str(result).unwrap();
    crate::task_identity::rewrite_identity(&mut v, "T", "C", skill);
    v
}

#[test]
fn a_task_keeps_its_order_and_spelling_and_takes_busbars_ids() {
    let far = r#"{ "status": {"state":"working", "message": {"taskId":"x","contextId":"y","n":1.50}},
        "id" : "far", "history":[{"contextId":"y"},{"role":"agent"}], "kind":"task", "contextId":"far-c" }"#;
    let out = spliced(far, None);
    assert_eq!(
        out,
        r#"{ "status": {"state":"working", "message": {"taskId":"T","contextId":"C","n":1.50}},
        "id" : "T", "history":[{"contextId":"C"},{"role":"agent"}], "kind":"task", "contextId":"C" }"#
    );
    assert_eq!(
        serde_json::from_str::<Value>(&out).unwrap(),
        valued(far, None)
    );
}

#[test]
fn a_missing_identity_member_is_appended_and_a_skill_lands_in_metadata() {
    for (far, skill) in [
        (r#"{}"#, Some("plan")),
        (r#"{"kind":"task"}"#, Some("plan")),
        (r#"{"kind":"task","metadata":{"a":1}}"#, Some("plan")),
        (r#"{"kind":"task","metadata":7}"#, Some("plan")),
        (r#"{"message":{"role":"agent","contextId":"far"}}"#, None),
        (r#"{"message":{"role":"agent","taskId":"far"}}"#, None),
        (r#"{"statusUpdate":{"status":{"state":"completed"}}}"#, None),
    ] {
        let out = spliced(far, skill);
        assert_eq!(
            serde_json::from_str::<Value>(&out).unwrap(),
            valued(far, skill),
            "{far} -> {out}"
        );
    }
    assert_eq!(
        spliced(r#"{"kind":"task"}"#, Some("plan")),
        r#"{"kind":"task","id":"T","contextId":"C","metadata":{"busbar/skill":"plan"}}"#
    );
}

#[test]
fn a_result_that_is_no_object_is_left_to_the_value_path() {
    assert_eq!(rewrite_identity(b"[1]", &WRAPPERS, "T", "C", None), None);
    assert_eq!(rewrite_identity(b"\"s\"", &WRAPPERS, "T", "C", None), None);
}

#[test]
fn the_reading_copy_reads_a_number_past_f64_and_keeps_the_rest() {
    let b = br#"{"a":1e400,"s":"1e400","b":-2E999,"c":12345678901234567890123}"#;
    let r = readable(b);
    assert_eq!(
        std::str::from_utf8(&r).unwrap(),
        r#"{"a":0,"s":"1e400","b":0,"c":12345678901234567890123}"#
    );
    assert!(serde_json::from_slice::<Value>(&r).is_ok());
    assert!(matches!(readable(br#"{"a":1}"#), Cow::Borrowed(_)));
}

#[test]
fn the_result_span_and_the_rewrap_keep_the_far_ends_bytes() {
    let env = br#"{"jsonrpc":"2.0","result": {"z":1, "a":2} ,"id":7}"#;
    let span = result_span(env).unwrap();
    assert_eq!(&env[span], br#"{"z":1, "a":2}"#);
    assert_eq!(
        rewrap(b" {\"z\":1,\"a\":2}\n", &json!(7)).unwrap(),
        br#"{"jsonrpc":"2.0","id":7,"result":{"z":1,"a":2}}"#
    );
    assert_eq!(
        rewrap(b"", &json!("x")).unwrap(),
        br#"{"jsonrpc":"2.0","id":"x","result":null}"#
    );
    assert!(rewrap(b"<html>", &json!(1)).is_err());
    assert!(rewrap(b"{} {}", &json!(1)).is_err());
}
