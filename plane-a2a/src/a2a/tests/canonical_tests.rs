// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! RFC 8785 conformance, judged by the RFC's OWN vectors rather than by our reading of it.

use super::*;
use serde_json::json;

fn c(v: &Value) -> String {
    canonicalize(v).expect("canonicalizable")
}

/// RFC 8785 section 3.2.3: members are sorted on the UTF-16 code units of their NAMES, and the
#[test]
fn object_members_sort_by_name() {
    let v = json!({
        "\u{20ac}": "Euro Sign",
        "\r": "Carriage Return",
        "1": "One",
        "\u{80}": "Control",
        "\u{1f600}": "Emoji",
        "\u{f8ff}": "Private Use",
        "": "Empty",
        "aa": "Two chars",
        "a": "One char",
    });

    let names: Vec<&str> = vec![
        "\"\"",
        "\"\\r\"",
        "\"1\"",
        "\"a\"",
        "\"aa\"",
        "\"\u{80}\"",
        "\"\u{20ac}\"",
        "\"\u{1f600}\"",
        "\"\u{f8ff}\"",
    ];
    let out = c(&v);
    let mut cursor = 0usize;
    for name in names {
        let at = out[cursor..]
            .find(name)
            .unwrap_or_else(|| panic!("`{name}` missing or out of order in {out}"));
        cursor += at + name.len();
    }
}

/// UTF-16 order is not code-point order, and the disagreement is the reason this is not left to the
#[test]
fn a_supplementary_name_sorts_below_a_high_bmp_name() {
    let out = c(&json!({ "\u{fffd}": 1, "\u{10000}": 2 }));
    let supplementary = out.find('\u{10000}').expect("supplementary name present");
    let bmp = out.find('\u{fffd}').expect("bmp name present");
    assert!(
        supplementary < bmp,
        "UTF-16 order puts the supplementary name first; got {out}"
    );
}

/// RFC 8785 section 3.2.2.2: the two-character escapes are used where they exist, `\u` only below
#[test]
fn strings_use_the_shortest_escape_and_nothing_more() {
    assert_eq!(
        c(&json!("\"\\\u{8}\u{c}\n\r\t")),
        r#""\"\\\b\f\n\r\t""#.to_string()
    );
    assert_eq!(c(&json!("\u{1}\u{1f}")), r#""\u0001\u001f""#.to_string());
    assert_eq!(c(&json!("\u{7f}")), "\"\u{7f}\"".to_string());
    assert_eq!(c(&json!("\u{20ac}\u{1f600}")), "\"\u{20ac}\u{1f600}\"");
}

/// RFC 8785 section 3.2.2.3 defers to ECMAScript `Number.prototype.toString`, where a whole number
#[allow(clippy::excessive_precision)]
#[test]
fn numbers_print_as_ecmascript() {
    assert_eq!(c(&json!(1.0)), "1");
    assert_eq!(c(&json!(-0.0f64)), "0");
    assert_eq!(c(&json!(0)), "0");
    assert_eq!(c(&json!(333333333.33333329)), "333333333.3333333");
    assert_eq!(c(&json!(1e30)), "1e+30");
    assert_eq!(c(&json!(1.0e-7)), "1e-7");
    assert_eq!(c(&json!(1e21)), "1e+21");

    assert_eq!(c(&json!(1e20)), "100000000000000000000");

    assert_eq!(c(&json!(1e-6)), "0.000001");
}

/// RFC 8785 section 3.2.2.3: a number is an IEEE-754 double whatever its spelling, so an integer
#[test]
fn a_large_integer_canonicalizes_as_its_double() {
    assert_eq!(c(&json!(9007199254740992u64)), "9007199254740992");
    assert_eq!(c(&json!(9007199254740993u64)), "9007199254740992");
    assert_eq!(c(&json!(9007199254740995u64)), "9007199254740996");
    assert_eq!(c(&json!(u64::MAX)), "18446744073709552000");
    assert_eq!(c(&json!(i64::MIN)), "-9223372036854776000");
    assert_eq!(c(&json!(i64::MIN + 1)), "-9223372036854776000");
    assert_eq!(c(&json!(-9007199254740993i64)), "-9007199254740992");
}

/// RFC 8785 Appendix B, the IEEE-754 to ECMAScript table, one row per vector. The hex is the double's
#[test]
fn rfc8785_appendix_b_number_vectors() {
    let rows: &[(u64, &str)] = &[
        (0x0000000000000000, "0"),
        (0x8000000000000000, "0"),
        (0x0000000000000001, "5e-324"),
        (0x8000000000000001, "-5e-324"),
        (0x7fefffffffffffff, "1.7976931348623157e+308"),
        (0xffefffffffffffff, "-1.7976931348623157e+308"),
        (0x4340000000000000, "9007199254740992"),
        (0xc340000000000000, "-9007199254740992"),
        (0x4430000000000000, "295147905179352830000"),
        (0x44b52d02c7e14af5, "9.999999999999997e+22"),
        (0x44b52d02c7e14af6, "1e+23"),
        (0x44b52d02c7e14af7, "1.0000000000000001e+23"),
        (0x444b1ae4d6e2ef4e, "999999999999999700000"),
        (0x444b1ae4d6e2ef4f, "999999999999999900000"),
        (0x444b1ae4d6e2ef50, "1e+21"),
        (0x3eb0c6f7a0b5ed8c, "9.999999999999997e-7"),
        (0x3eb0c6f7a0b5ed8d, "0.000001"),
        (0x41b3de4355555553, "333333333.3333332"),
        (0x41b3de4355555554, "333333333.33333325"),
        (0x41b3de4355555555, "333333333.3333333"),
        (0x41b3de4355555556, "333333333.3333334"),
        (0x41b3de4355555557, "333333333.33333343"),
        (0xbecbf647612f3696, "-0.0000033333333333333333"),
        (0x43143ff3c1cb0959, "1424953923781206.2"),
    ];
    for (bits, want) in rows {
        let f = f64::from_bits(*bits);
        let v = Value::Number(serde_json::Number::from_f64(f).expect("finite"));
        assert_eq!(c(&v), *want, "bits {bits:#018x}");
    }
}

/// The same table reached through the PARSER, since that is the path a card takes: text to `Value`
#[test]
fn parsed_number_spellings_canonicalize_as_doubles() {
    for (text, want) in [
        ("9007199254740993", "9007199254740992"),
        ("18446744073709551615", "18446744073709552000"),
        ("1E30", "1e+30"),
        ("1.0e+2", "100"),
        ("123456789012345678901234567890", "1.2345678901234568e+29"),
        ("5e-324", "5e-324"),
        ("1e-7", "1e-7"),
        ("[1.7976931348623157e308]", "[1.7976931348623157e+308]"),
    ] {
        let v: Value = serde_json::from_str(text).expect("parses");
        assert_eq!(c(&v), want, "input {text}");
    }
}

/// Whitespace is not canonical, and neither is anything decorative. The canonical form of a
#[test]
fn two_spellings_of_one_document_canonicalize_identically() {
    let pretty: Value =
        serde_json::from_str("{\n  \"b\" : [ 1, 2 ],\n  \"a\" : { \"z\": 1.0, \"y\": true }\n}")
            .expect("parse");
    let terse: Value = serde_json::from_str(r#"{"a":{"y":true,"z":1},"b":[1,2]}"#).expect("parse");
    assert_eq!(c(&pretty), c(&terse));
    assert_eq!(c(&terse), r#"{"a":{"y":true,"z":1},"b":[1,2]}"#);
}

/// ARRAY order is data, not presentation, so it is preserved exactly. Sorting an array would make
#[test]
fn array_order_is_preserved() {
    assert_eq!(c(&json!([3, 1, 2])), "[3,1,2]");
    assert_ne!(c(&json!([3, 1, 2])), c(&json!([1, 2, 3])));
}

/// NON-FINITE NUMBERS ARE UNREPRESENTABLE BEFORE THEY REACH THE CANONICALIZER — which is the honest
#[test]
fn a_non_finite_number_cannot_be_built_into_a_value_at_all() {
    assert!(serde_json::Number::from_f64(f64::NAN).is_none());
    assert!(serde_json::Number::from_f64(f64::INFINITY).is_none());
    assert!(serde_json::Number::from_f64(f64::NEG_INFINITY).is_none());

    assert_eq!(
        serde_json::to_value(f64::NAN).expect("to_value"),
        Value::Null
    );
    assert_eq!(
        c(&serde_json::to_value(f64::NAN).expect("to_value")),
        "null"
    );

    let mut map = serde_json::Map::new();
    map.insert(
        "x".to_string(),
        Value::Number(serde_json::Number::from_f64(1.0).expect("finite")),
    );
    assert_eq!(
        canonicalize(&Value::Object(map)),
        Ok(r#"{"x":1}"#.to_string())
    );
}

/// Empty containers still canonicalize, and an absent member is not an empty one. A card that
#[test]
fn empty_containers_are_distinct_from_absent_ones() {
    assert_eq!(c(&json!({})), "{}");
    assert_eq!(c(&json!([])), "[]");
    assert_ne!(c(&json!({ "skills": [] })), c(&json!({})));
    assert_ne!(
        c(&json!({ "skills": Value::Null })),
        c(&json!({ "skills": [] }))
    );
}
