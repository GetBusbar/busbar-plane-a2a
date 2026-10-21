// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Per-plane diagnostics-catalog invariants for the A2A plane: code/slug uniqueness, the
//! class↔code thousands-digit contract, and the live-entry documentation floor. The committed
//! markdown/JSON snapshot tests render through the host's renderers, which this crate does not
//! link, so they run where those renderers are linked.

use super::*;

/// THE CATALOG IS NOT EMPTY, AND NOT ENTIRELY RETIRED.
///
/// Every other test in this file is a `for d in DIAGNOSTICS` loop whose assertions live INSIDE the
/// loop, and `every_live_entry_documents_meaning_and_action` additionally `continue`s past every
/// retired entry. A catalog that regressed to empty — a bad `cfg` gate, a botched merge — would
/// therefore make all four of them pass green while every documented diagnostic silently
/// disappeared. This is the floor that makes those loops mean something.
#[test]
fn the_catalog_is_not_empty() {
    assert!(
        !DIAGNOSTICS.is_empty(),
        "the diagnostics catalog is empty, which makes every loop test in this file vacuous"
    );
    assert!(
        DIAGNOSTICS.iter().any(|d| !d.retired),
        "the catalog holds nothing but retired entries, which makes \
         `every_live_entry_documents_meaning_and_action` vacuous"
    );
}

/// Codes are unique within this plane's catalog — a collision would make one un-resolvable.
#[test]
fn codes_are_unique() {
    let mut seen = std::collections::BTreeSet::new();
    for d in DIAGNOSTICS.iter().chain(RESERVED) {
        assert!(
            seen.insert(d.code),
            "duplicate code {} ({})",
            d.code,
            d.slug
        );
    }
}

/// The thousands digit of every code equals its class ordinal, and the x000 slot is reserved.
#[test]
fn code_thousands_digit_matches_class() {
    for d in DIAGNOSTICS.iter().chain(RESERVED) {
        assert_eq!(
            d.code / 1000,
            d.class.ordinal(),
            "{} ({}) class/code mismatch",
            d.banner(),
            d.slug
        );
        assert!(
            d.code % 1000 != 0,
            "{} ({}) uses the reserved x000 slot",
            d.banner(),
            d.slug
        );
    }
}

/// Slugs are unique, non-empty, kebab-case — they are stable doc anchors and URL fragments.
#[test]
fn slugs_are_unique_and_kebab_case() {
    let mut seen = std::collections::BTreeSet::new();
    for d in DIAGNOSTICS.iter().chain(RESERVED) {
        assert!(
            seen.insert(d.slug),
            "duplicate slug {:?} (code {})",
            d.slug,
            d.code
        );
        assert!(!d.slug.is_empty(), "{} has an empty slug", d.banner());
        assert!(
            d.slug
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
            "slug {:?} (code {}) is not kebab-case",
            d.slug,
            d.code
        );
        assert!(
            !d.slug.starts_with('-') && !d.slug.ends_with('-') && !d.slug.contains("--"),
            "slug {:?} (code {}) has a leading/trailing/double hyphen",
            d.slug,
            d.code
        );
    }
}

/// Every non-retired entry documents its meaning and an action.
#[test]
fn every_live_entry_documents_meaning_and_action() {
    for d in DIAGNOSTICS {
        if d.retired {
            continue;
        }
        assert!(
            d.summary.len() > 20,
            "{} ({}) has no real summary",
            d.banner(),
            d.slug
        );
        assert!(
            d.action.len() > 3,
            "{} ({}) has no action",
            d.banner(),
            d.slug
        );
    }
}

/// THE PLANE'S `declares.json` STATES ITS CATALOGUE: the `diagnostics` the door's Statement carries
/// (and the release signs into a dropped-in plane's manifest), from which the host installs the
/// plane's codes in either build, are exactly the entries [`DIAGNOSTICS`] holds, field for field,
/// beside the plane's breaker fact and its needs.
#[test]
fn the_declares_file_states_the_catalogue() {
    let declared: serde_json::Value =
        serde_json::from_str(include_str!("../../declares.json")).expect("declares.json is JSON");
    let want: Vec<serde_json::Value> = DIAGNOSTICS
        .iter()
        .map(|d| {
            serde_json::json!({
                "code": d.code,
                "slug": d.slug,
                "title": d.title,
                "severity": d.severity.as_str(),
                "summary": d.summary,
                "action": d.action,
                "since": d.since,
            })
        })
        .collect();
    // The breaker fact (ARCHITECT Q4): a transient failure below the trip threshold never benches
    // an agent's cell; and the carriers the plane needs.
    let whole = serde_json::json!({
        "breaker": { "bench_below_trip_threshold": false },
        "diagnostics": want,
        "needs": ["grpc", "http"],
    });
    assert_eq!(
        declared,
        whole,
        "declares.json drifted from the catalogue; expected:\n{}",
        serde_json::to_string_pretty(&whole).unwrap()
    );
}

/// THE CATALOGUE IS THE CODES THE PLANE CAN RAISE: every diagnostic the plane's own source (its
/// tests aside) names is in [`DIAGNOSTICS`], and every entry there is named by it, so a code the
/// plane starts to raise cannot go undeclared and a code it stops raising cannot stay declared.
#[test]
fn the_catalogue_is_the_codes_the_plane_names() {
    use std::path::Path;
    fn walk(dir: &Path, out: &mut String) {
        for entry in std::fs::read_dir(dir).expect("the source reads").flatten() {
            let path = entry.path();
            if path.is_dir() {
                if path.file_name().is_some_and(|n| n != "tests") {
                    walk(&path, out);
                }
            } else if path.extension().is_some_and(|e| e == "rs")
                && path.file_name().is_some_and(|n| n != "diagnostics.rs")
            {
                out.push_str(&std::fs::read_to_string(&path).expect("a source file reads"));
                out.push('\n');
            }
        }
    }
    let mut source = String::new();
    walk(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut source,
    );
    let catalogue = include_str!("../diagnostics.rs");
    let named = |name: &str| {
        source.match_indices(name).any(|(at, _)| {
            let before = source[..at].chars().next_back();
            let after = source[at + name.len()..].chars().next();
            let ident = |c: Option<char>| c.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_');
            !ident(before) && !ident(after)
        })
    };
    let mut raised = std::collections::BTreeSet::new();
    for line in catalogue.lines() {
        let Some(name) = line
            .strip_prefix("pub const ")
            .and_then(|rest| rest.strip_suffix(": Diagnostic = Diagnostic {"))
        else {
            continue;
        };
        if named(name) {
            raised.insert(name.to_string());
        }
    }
    let declared: std::collections::BTreeSet<String> = DIAGNOSTICS
        .iter()
        .map(|d| {
            catalogue
                .lines()
                .zip(catalogue.lines().skip(1))
                .find(|(_, next)| next.trim() == format!("code: {},", d.code))
                .and_then(|(line, _)| line.strip_prefix("pub const "))
                .and_then(|rest| rest.strip_suffix(": Diagnostic = Diagnostic {"))
                .expect("every catalogue entry is a `pub const` whose first member is its code")
                .to_string()
        })
        .collect();
    assert!(
        !raised.is_empty(),
        "the scan found no diagnostic the plane names"
    );
    assert_eq!(
        raised, declared,
        "the codes the plane's source names are not the catalogue it declares"
    );
}
