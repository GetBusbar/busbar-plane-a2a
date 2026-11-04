// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Owned request JSON wipes what a failed or superseded parse leaves behind.

use super::RequestJson;

#[test]
fn malformed_later_array_item_wipes_the_initialized_prior_value() {
    crate::tests::request_custody_probe::assert_wiped(|| {
        let input = br#"["callback-credential-custody-canary",{"unfinished":]"#;
        assert!(serde_json::from_slice::<RequestJson>(input).is_err());
    });
}

#[test]
fn duplicate_object_member_wipes_its_superseded_value() {
    crate::tests::request_custody_probe::assert_wiped(|| {
        let input =
            br#"{"credential":"callback-credential-custody-canary","credential":"replacement"}"#;
        let document: RequestJson = serde_json::from_slice(input).unwrap();
        assert_eq!(document["credential"], "replacement");
    });
}

#[test]
fn escaped_credentials_are_decoded_in_wiping_owners() {
    crate::tests::request_custody_probe::assert_wiped(|| {
        let input = br#"{"credential":"callback\u002dcredential-custody-canary","unicode":"\ud83d\ude00","controls":"\b\f\n\r\t"}"#;
        let document = super::parse(input).expect("valid escapes");
        assert_eq!(document["credential"], "callback-credential-custody-canary");
        assert_eq!(document["unicode"], "😀");
        assert_eq!(document["controls"], "\u{8}\u{c}\n\r\t");
    });
}

#[test]
fn guarded_decoder_preserves_json_values_and_rejects_invalid_unicode() {
    for bytes in [
        br#"null"#.as_slice(),
        br#"[true,false,-1,1.25,1e10]"#,
        br#"{"a":[{"b":"x\\y\"z"}],"a":null}"#,
    ] {
        let expected: serde_json::Value = serde_json::from_slice(bytes).unwrap();
        assert_eq!(*super::parse(bytes).unwrap(), expected);
    }
    for bytes in [
        br#""\ud800""#.as_slice(),
        br#""\udc00""#,
        br#""\ud800\u0041""#,
        br#"[1e999]"#,
        b"\"\xff\"",
        br#"{"a":true,}"#,
    ] {
        assert!(super::parse(bytes).is_err(), "{bytes:?}");
        assert!(!super::valid(bytes), "{bytes:?}");
    }
}

#[test]
fn strict_typed_decoder_rejects_duplicate_keys_before_projection() {
    let input = br#"{"credential":"first","credential":"last"}"#;
    assert!(super::from_slice::<RequestJson>(input).is_err());
    assert_eq!(super::parse(input).unwrap()["credential"], "last");
}

#[test]
fn malformed_typed_decode_wipes_the_guarded_input_document() {
    crate::tests::request_custody_probe::assert_wiped(|| {
        let input = br#"{"credential":"callback\u002dcredential-custody-canary"}"#;
        assert!(super::from_slice::<Vec<String>>(input).is_err());
    });
}

#[test]
fn wire_decoder_only_delegates_string_free_inputs_to_serde_scratch() {
    let source = include_str!("../request_json_decode.rs");
    assert!(source.contains("serde_json::from_slice::<serde::de::IgnoredAny>"));
    assert!(source.contains("Value::Number(serde_json::from_slice(raw).ok()?)"));
    assert_eq!(source.matches("serde_json::from_slice").count(), 3);
    assert!(source.contains("String::with_capacity(raw.len())"));
}
