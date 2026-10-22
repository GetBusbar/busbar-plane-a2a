// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE'S TRUST IS THE KERNEL'S: the a2a plane's source declares no trust machine of its own.
//! This is the choke point's one class test (busbar's structure-lint choke-point registry, row G,
//! names `crates/busbar-plane-a2a/tests/purity.rs::the_a2a_plane_declares_no_trust_state_of_its_own`),
//! so it lives at that path. It reads the crate's source off disk and names no crate item; the
//! crate's other purity scans are its unit tests (`src/tests/purity.rs`).

use std::path::{Path, PathBuf};

/// The crate's own source directory.
fn src_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

/// Walk every source file, handing each to a reader.
fn walk(dir: &Path, f: &mut impl FnMut(&Path, &str)) {
    for entry in std::fs::read_dir(dir)
        .expect("the source directory is readable")
        .flatten()
    {
        let path = entry.path();
        // The crate's test modules (`src/tests`, `src/a2a/tests`) are not the plane: they read
        // fixtures and the environment, as tests do.
        if path.is_dir() && path.file_name().is_some_and(|n| n == "tests") {
            continue;
        }
        if path.is_dir() {
            walk(&path, f);
        } else if path.extension().is_some_and(|e| e == "rs") {
            let text = std::fs::read_to_string(&path).expect("a source file is readable");
            f(&path, &text);
        }
    }
}

/// A line that is only a comment says nothing about what the code does.
fn is_comment(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("//") || t.starts_with("*") || t.starts_with("/*")
}

/// THE PLANE DECLARES NO TRUST STATE OF ITS OWN.
///
/// Ported from the deleted engine crate's `reuse_tests::the_a2a_plane_declares_no_trust_state_of_its_own`.
/// The trust lifecycle (the states, the drift, the approval, the pinned artifact and the verbs that
/// move a registration through them) is the kernel's, written once and plane-neutral. The plane
/// contributes its report types (`Sighting`, `CardObservation`: what a look saw) and parameterises the
/// machine over them; a second declaration of the machine here is a fork, and two machines disagree
/// the first time one of them is fixed. The sources are enumerated off disk (a hand-kept file list
/// silently stops covering the newest code), and a scan that finds nothing is a failure, not a pass.
#[test]
fn the_a2a_plane_declares_no_trust_state_of_its_own() {
    const BANNED: &[&str] = &[
        "enum TrustState",
        "enum Drift",
        "struct Approval",
        "trait PinnedArtifact",
        "fn serves",
        "fn suspend",
        "fn resume",
        "fn unpin",
    ];
    let mut scanned = 0usize;
    let mut offenders = Vec::new();
    walk(&src_dir(), &mut |path, text| {
        scanned += 1;
        for (n, line) in text.lines().enumerate() {
            if is_comment(line) {
                continue;
            }
            for needle in BANNED {
                if line.contains(needle) {
                    offenders.push(format!("{}:{}: `{needle}`", path.display(), n + 1));
                }
            }
        }
    });
    assert!(
        scanned >= 4,
        "the scan found {scanned} source file(s), which cannot be right: a scan that discovers \
         nothing passes vacuously"
    );
    assert!(
        offenders.is_empty(),
        "the plane forks the trust machine, which is the kernel's and plane-neutral: {offenders:?}"
    );
}
