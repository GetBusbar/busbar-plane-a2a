//! This plane is the same plane everywhere it is compiled.
//!
//! A plane compiled two ways is two planes, and the kernel would have no way to tell which one it
//! registered. The contract crate holds itself to that rule and asserts it; this is the same
//! assertion, one crate over, for the same reason.

use std::path::{Path, PathBuf};

/// The crate's own source directory.
fn src_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

/// The crate's own manifest.
fn manifest() -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
        .expect("the manifest is readable")
}

/// Walk every source file, handing each to a reader.
fn walk(dir: &Path, f: &mut impl FnMut(&Path, &str)) {
    for entry in std::fs::read_dir(dir)
        .expect("the source directory is readable")
        .flatten()
    {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, f);
        } else if path.extension().is_some_and(|e| e == "rs") {
            let text = std::fs::read_to_string(&path).expect("a source file is readable");
            f(&path, &text);
        }
    }
}

/// The manifest declares no features at all.
#[test]
fn the_crate_declares_no_features() {
    let manifest = manifest();
    assert!(
        !manifest.contains("[features]"),
        "the plane declares cargo features, so it is not one plane"
    );
    assert!(
        !manifest.contains("optional = true"),
        "an optional dependency is a feature by another name"
    );
}

/// No item on the surface is behind a conditional-compilation attribute.
///
/// Test modules are exempt, because a test module is not on the surface: it is compiled only when
/// the tests are, and the kernel never sees it.
#[test]
fn no_item_is_conditionally_compiled() {
    let mut offenders = Vec::new();
    walk(&src_dir(), &mut |path, text| {
        for (n, line) in text.lines().enumerate() {
            let line = line.trim_start();
            if line.starts_with("#[cfg(test)]") {
                continue;
            }
            if line.starts_with("#[cfg(") || line.starts_with("#![cfg(") {
                offenders.push(format!("{}:{}", path.display(), n + 1));
            }
        }
    });
    assert!(
        offenders.is_empty(),
        "conditionally compiled items: {offenders:?}"
    );
}

/// The crate carries the two lint gates the design requires of a plugin: the literal
/// `#![forbid(unsafe_code)]` (BUSBAR-1.6.0.md l.273), in the test build as in the shipped one, and
/// no `cfg_attr` that would loosen it (ARCHITECT ruling 2026-10-21: the allocation gates' counter
/// is busbar-test-kit's `alloc_counter`).
#[test]
fn the_crate_forbids_unsafe_and_undocumented_items() {
    let lib = std::fs::read_to_string(src_dir().join("lib.rs")).expect("the root is readable");
    assert!(lib.lines().any(|l| l.trim() == "#![forbid(unsafe_code)]"));
    assert!(!lib.contains("cfg_attr(not(test), forbid(unsafe_code))"));
    assert!(!lib.contains("cfg_attr(test, deny(unsafe_code))"));
    assert!(lib.contains("#![deny(missing_docs)]"));
}

/// No source file contains the word the lint gate forbids, the crate's test modules (`src/tests`,
/// `src/a2a/tests`) included: they compile under the same literal `forbid`.
#[test]
fn the_source_contains_no_unsafe_block() {
    let mut offenders = Vec::new();
    walk(&src_dir(), &mut |path, text| {
        for (n, line) in text.lines().enumerate() {
            let t = line.trim_start();
            if t.starts_with("//") {
                continue;
            }
            if line.contains("unsafe ") {
                offenders.push(format!("{}:{}", path.display(), n + 1));
            }
        }
    });
    assert!(
        offenders.is_empty(),
        "unsafe code on the surface: {offenders:?}"
    );
}

/// THE OTHER PLANES, by crate name: the fixed list every plane's sibling check names (lead ruling
/// D33). A prefix scan over a `crates/` directory or a `busbar-plane-` family would be vacuous in a
/// standalone repo, so the names are stated, each with its cdylib twin.
const SIBLING_PLANES: &[&str] = &[
    "busbar-plane-llm",
    "busbar-plane-llm-plugin",
    "busbar-plane-mcp",
    "busbar-plane-mcp-plugin",
    "busbar-plane-streaming",
    "busbar-plane-streaming-plugin",
    "busbar-plane-decisions",
    "busbar-plane-decisions-plugin",
];

/// Every crate a manifest's dependency tables name, each as `(the key, the package it renames)`:
/// the `[dependencies]`, `[dev-dependencies]` and `[build-dependencies]` tables, their
/// `[target.<cfg>.*]` forms, and the `[dependencies.<name>]` table form, so neither a table header
/// nor a `package = "..."` rename hides a crate.
fn dependencies(manifest: &str) -> Vec<(String, Option<String>)> {
    // The table being read: a dependency list, or one dependency's own table (its index in
    // `found`).
    enum Table {
        Other,
        List,
        One(usize),
    }
    let kinds = ["dependencies", "dev-dependencies", "build-dependencies"];
    let unquote = |v: &str| v.trim().trim_matches('"').to_string();
    let package_of = |v: &str| {
        v.split("package")
            .nth(1)
            .and_then(|rest| rest.trim_start().strip_prefix('='))
            .and_then(|rest| rest.trim_start().strip_prefix('"'))
            .and_then(|rest| rest.split('"').next())
            .map(str::to_string)
    };
    let mut found: Vec<(String, Option<String>)> = Vec::new();
    let mut table = Table::Other;
    for line in manifest.lines() {
        let line = line.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        if let Some(header) = line.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
            let header = header.trim();
            let path: Vec<&str> = header.split('.').map(str::trim).collect();
            let at = path.iter().position(|seg| kinds.contains(seg));
            table = match at {
                // `[dependencies]` or `[target.<cfg>.dependencies]`.
                Some(i) if i + 1 == path.len() && (i == 0 || path[0] == "target") => Table::List,
                // `[dependencies.<name>]` or `[target.<cfg>.dependencies.<name>]`.
                Some(i) if i + 2 == path.len() && (i == 0 || path[0] == "target") => {
                    found.push((unquote(path[i + 1]), None));
                    Table::One(found.len() - 1)
                }
                _ => Table::Other,
            };
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match table {
            Table::List => found.push((unquote(key), package_of(value))),
            Table::One(i) if key.trim() == "package" => found[i].1 = Some(unquote(value)),
            Table::One(_) | Table::Other => {}
        }
    }
    found
}

/// The manifest names the contract, the codec and the serializer, and nothing kernel-side, and no
/// other plane: no dependency, by its key or by the package a rename points at, in any dependency
/// table.
#[test]
fn the_manifest_names_only_what_a_plane_may_name() {
    let deps = dependencies(&manifest());
    assert!(
        deps.iter().any(|(name, _)| name == "busbar-contract"),
        "the manifest's dependencies were read: {deps:?}"
    );
    for (key, package) in &deps {
        for name in std::iter::once(key).chain(package) {
            for forbidden in [
                "busbar-core",
                "busbar-substrate",
                "busbar-caps",
                "busbar-kernel",
                "busbar-unit-",
            ] {
                assert!(
                    !name.starts_with(forbidden),
                    "the plane depends on {name}, which is kernel-side"
                );
            }
            // No plane depends on a sibling plane's crate — the broker law (DECISION #8): planes
            // never talk to each other.
            assert!(
                !SIBLING_PLANES.contains(&name.as_str()),
                "the plane depends on sibling plane crate {name}"
            );
        }
    }
}

/// The manifest reading sees a sibling however it is spelled: a table header, a rename, a target
/// table, a dev or build dependency.
#[test]
fn a_sibling_is_seen_however_the_manifest_spells_it() {
    for spelled in [
        "[dependencies]\nbusbar-plane-llm = \"1\"\n",
        "[dependencies]\nllm = { package = \"busbar-plane-mcp\", version = \"1\" }\n",
        "[dependencies.busbar-plane-streaming]\nversion = \"1\"\n",
        "[dependencies.x]\npackage = \"busbar-plane-decisions\"\n",
        "[target.'cfg(unix)'.dependencies]\nbusbar-plane-llm-plugin = \"1\"\n",
        "[dev-dependencies]\nbusbar-plane-mcp = { path = \"../mcp\" }\n",
    ] {
        let deps = dependencies(spelled);
        assert!(
            deps.iter().any(|(key, package)| std::iter::once(key)
                .chain(package)
                .any(|n| SIBLING_PLANES.contains(&n.as_str()))),
            "not seen in {spelled:?}: {deps:?}"
        );
    }
}

/// The comments cite the design in words, not in section numbers or binding identifiers.
///
/// A section number in a comment is a cross-reference that rots the first time the document is
/// renumbered, and the design says as much: cite the section in words.
#[test]
fn the_comments_cite_the_design_in_words() {
    let mut offenders = Vec::new();
    let mut check = |path: &Path, text: &str| {
        for (n, line) in text.lines().enumerate() {
            if line.contains('\u{a7}') {
                offenders.push(format!("{}:{}: section sign", path.display(), n + 1));
            }
            let bytes = line.as_bytes();
            for i in 0..bytes.len().saturating_sub(4) {
                if bytes[i] == b'P'
                    && bytes[i + 1] == b'B'
                    && bytes[i + 2] == b'-'
                    && bytes[i + 3].is_ascii_digit()
                {
                    offenders.push(format!("{}:{}: binding identifier", path.display(), n + 1));
                }
            }
        }
    };
    walk(&src_dir(), &mut check);
    walk(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests"),
        &mut check,
    );
    let manifest_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    check(&manifest_path, &manifest());
    assert!(
        offenders.is_empty(),
        "the source cites the design by number rather than in words: {offenders:?}"
    );
}

/// Ported from busbar-a2a a2a/tests/sign_tests.rs::there_is_exactly_one_canonicalizer_and_one_signing_payload_on_this_plane.
///
/// The source-level half, with a floor. Two canonicalizers disagree the first time either one is
/// fixed, and the disagreement is invisible until a real vendor's card contains a number, a
/// supplementary-plane character in an extension key, or a member busbar does not model. So the
/// ratchet is on the COUNT of definitions, not on a comment saying they are shared: one
/// canonicalizer, one signing payload, and the signing path calls both.
#[test]
fn there_is_exactly_one_canonicalizer_and_one_signing_payload_on_this_plane() {
    let mut files = 0usize;
    let mut canonicalizers = Vec::new();
    let mut payloads = Vec::new();
    let mut sign_uses_them = false;
    walk(&src_dir(), &mut |path, text| {
        files += 1;
        let code: String = text
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        if code.contains("fn canonicalize(") {
            canonicalizers.push(path.display().to_string());
        }
        if code.contains("fn signing_payload(") {
            payloads.push(path.display().to_string());
        }
        if path.file_name().is_some_and(|n| n == "served_card.rs") {
            sign_uses_them =
                code.contains("signing_payload(card)") && code.contains("canonicalize(");
        }
    });
    assert!(
        files >= 20,
        "the scan found {files} source file(s), which cannot be right: a scan that discovers \
         nothing passes vacuously"
    );
    assert_eq!(
        canonicalizers.len(),
        1,
        "exactly one canonicalizer may exist on this plane; found {canonicalizers:?}"
    );
    assert_eq!(
        payloads.len(),
        1,
        "exactly one signing-payload definition may exist on this plane; found {payloads:?}"
    );
    assert!(
        sign_uses_them,
        "the SIGNING half must call the same `signing_payload` and the same `canonicalize` the \
         VERIFYING half calls, rather than serializing a document of its own"
    );
}
