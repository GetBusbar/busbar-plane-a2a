//! The plane is pure, and this is what says so.
//!
//! A plane is pure over its inputs and performs no input or output of its own. Those are two
//! separate claims and they are checked two separate ways: the source is walked for the shapes that
//! would make either false, and the door's arrival is driven repeatedly over the same inputs and its
//! answers compared. A comment claiming purity is worth nothing; a scan and a repeat are worth something.

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

/// THE GENERATED MESSAGES (`build.rs`, the gRPC line's `lf.a2a.v1` package): the plane's source
/// includes them from the build's output directory, so the scans read them as the plane's own
/// source and read the include line itself as what it is, a compile-time inclusion.
const GENERATED: &[&str] = &["lf.a2a.v1.rs", "lf.a2a.v1.serde.rs", "method_inventory.rs"];

/// Every source file of the plane: its own, then the generated messages it includes.
fn each_source(f: &mut impl FnMut(&Path, &str)) {
    walk(&src_dir(), f);
    for name in GENERATED {
        let path = Path::new(env!("OUT_DIR")).join(name);
        let text = std::fs::read_to_string(&path).expect("the generated source is readable");
        f(&path, &text);
    }
}

/// The plane's inclusion of one [`GENERATED`] file, whose text [`each_source`] scans in its place.
fn is_generated_include(line: &str) -> bool {
    // The macro's name is spliced in so this file holds no include of its own for a scan of the
    // crate's build inputs to read.
    let t = line.trim();
    GENERATED
        .iter()
        .any(|name| t == format!("{}!(concat!(env!(\"OUT_DIR\"), \"/{name}\"));", "include"))
}

/// A line that is only a comment says nothing about what the code does.
fn is_comment(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("//") || t.starts_with("*") || t.starts_with("/*")
}

/// The plane's source spells no interior-mutability primitive of its own.
///
/// What this checks is the spelling, not the absence of state: the plane DOES keep state across
/// calls (its units, held cards, trust, flights and deliveries), and all of it lives in the SDK's
/// `Keyed` maps on the door's instance, which this scan does not and cannot see. What it holds the
/// plane to is that no cell, lock, atomic or global of its own sits beside those maps, where state
/// could change an answer outside the one keyed store the instance owns.
#[test]
fn the_plane_spells_no_interior_mutability_of_its_own() {
    let forbidden = [
        "Cell<",
        "RefCell",
        "UnsafeCell",
        "Mutex<",
        "RwLock",
        // Every atomic type, not four spellings of one: `AtomicI64`, `AtomicPtr`, ... alike.
        "Atomic",
        "Condvar",
        "sync::Once",
        "Once::new",
        "OnceLock",
        "OnceCell",
        "LazyLock",
        "lazy_static",
        "thread_local",
        "static mut",
    ];
    let mut offenders = Vec::new();
    each_source(&mut |path, text| {
        for (n, line) in text.lines().enumerate() {
            if is_comment(line) || is_generated_include(line) {
                continue;
            }
            for name in forbidden {
                if line.contains(name) {
                    offenders.push(format!("{}:{}: {name}", path.display(), n + 1));
                }
            }
        }
    });
    assert!(
        offenders.is_empty(),
        "the plane spells interior mutability of its own: {offenders:?}"
    );
}

/// The plane performs no input and no output.
///
/// Not a socket, not a file, not a process, not a thread, not a system clock. The one clock a plane
/// may read is the one the context hands it, which is why the system clock is on this list.
#[test]
fn the_plane_performs_no_input_or_output() {
    let forbidden = [
        "std::fs",
        "std::net",
        "std::process",
        "std::thread",
        "std::io",
        "SystemTime",
        "Instant::now",
        "tokio",
        "reqwest",
        "async fn",
        "await",
        "env!",
        "std::env",
        "println!",
        "eprintln!",
    ];
    let mut offenders = Vec::new();
    each_source(&mut |path, text| {
        for (n, line) in text.lines().enumerate() {
            if is_comment(line) || is_generated_include(line) {
                continue;
            }
            for name in forbidden {
                if line.contains(name) {
                    offenders.push(format!("{}:{}: {name}", path.display(), n + 1));
                }
            }
        }
        // A GROUPED IMPORT (`use std::{env, fs};`, rustfmt's merged form) spells none of the paths
        // above, so each `std::{ ... }` group is read for the modules it names.
        for named in std_group_modules(text) {
            if ["fs", "net", "process", "thread", "io", "env"].contains(&named.as_str()) {
                offenders.push(format!("{}: std::{{{named}}}", path.display()));
            }
        }
    });
    assert!(
        offenders.is_empty(),
        "the plane reaches outside itself: {offenders:?}"
    );
}

/// The first path segment of every member of every `std::{ ... }` group in `text` (comment lines
/// dropped), nested groups read too: `use std::{env, io::Read};` names `env` and `io`.
fn std_group_modules(text: &str) -> Vec<String> {
    let code: String = text
        .lines()
        .filter(|l| !is_comment(l))
        .collect::<Vec<_>>()
        .join("\n");
    let mut named = Vec::new();
    for (at, _) in code.match_indices("std::{") {
        let body = &code[at + "std::{".len()..];
        let mut depth = 0usize;
        let mut member = String::new();
        let mut members = Vec::new();
        for c in body.chars() {
            match c {
                '{' => depth += 1,
                '}' if depth == 0 => break,
                '}' => depth -= 1,
                ',' if depth == 0 => members.push(std::mem::take(&mut member)),
                _ => {}
            }
            if depth == 0 && c != ',' && c != '}' {
                member.push(c);
            }
        }
        members.push(member);
        named.extend(
            members
                .iter()
                .filter_map(|m| m.trim().split("::").next())
                .map(|m| m.trim().to_string())
                .filter(|m| !m.is_empty()),
        );
    }
    named
}

/// The scan of a grouped `std` import reads the modules it names, nested and across lines.
#[test]
fn a_grouped_std_import_is_read_for_its_modules() {
    assert_eq!(
        std_group_modules("use std::{env, fs};\nuse std::{\n    collections::BTreeMap,\n    io::{Read, Write},\n};"),
        ["env", "fs", "collections", "io"]
    );
}

/// THE OTHER PLANES' CRATES as source names them (`tests/invariance.rs` `SIBLING_PLANES`, the
/// fixed list of lead ruling D33): a cdylib twin's name starts with its plane's, so each covers
/// both.
const SIBLING_PLANE_CRATES: &[&str] = &[
    "busbar_plane_llm",
    "busbar_plane_mcp",
    "busbar_plane_streaming",
    "busbar_plane_decisions",
];

/// The plane names no kernel-side crate.
///
/// The manifest allow-list is the real control; this is the same rule asserted from the inside, so a
/// reach for the kernel is a red here rather than a discovery at packaging time.
#[test]
fn the_plane_names_no_kernel_side_crate() {
    let forbidden = [
        "busbar_contract::caps",
        "busbar_kernel",
        "busbar_unit",
        "busbar_substrate",
    ];
    let mut offenders = Vec::new();
    each_source(&mut |path, text| {
        for (n, line) in text.lines().enumerate() {
            if is_comment(line) || is_generated_include(line) {
                continue;
            }
            for name in forbidden {
                if line.contains(name) {
                    offenders.push(format!("{}:{}: {name}", path.display(), n + 1));
                }
            }
            // No plane names a sibling plane crate — same broker law (DECISION #8), and the same
            // fixed list of the other planes (lead ruling D33), as the manifest-level check in
            // `tests/invariance.rs`, asserted here from the source side. (A renamed dependency
            // is that check's to catch: the manifest is where a rename is spelled.)
            for sibling in SIBLING_PLANE_CRATES {
                if line.contains(sibling) {
                    offenders.push(format!("{}:{}: {sibling}", path.display(), n + 1));
                }
            }
        }
    });
    assert!(
        offenders.is_empty(),
        "the plane names kernel-side crates: {offenders:?}"
    );
}

/// The door's arrival gives the same answer every time it is asked the same question.
#[test]
fn the_arrival_is_deterministic() {
    let bodies: Vec<Vec<u8>> = crate::ops::OP_CLASSES
        .iter()
        .filter_map(|op| crate::ops::METHODS.iter().find(|r| r.op == *op))
        .map(|row| {
            format!(
                r#"{{"jsonrpc":"2.0","id":5,"method":"{}","params":{{"id":"t1"}}}}"#,
                row.method
            )
            .into_bytes()
        })
        .collect();
    // The bodies are DERIVED — a filter over one declared table looked up in another — so an
    // op class dropped from the first, or a method row dropped from the second, empties this
    // vector and the loop below runs zero times. A determinism test that examined nothing would
    // report `ok`, which is the shape this assertion exists to make impossible.
    assert!(
        !bodies.is_empty(),
        "no request body was derived from the declared op classes, so nothing was driven twice"
    );
    for body in &bodies {
        let answers: Vec<String> = (0..8)
            .map(|_| {
                format!(
                    "{:?}",
                    crate::agent_arrival::decide_and_read(body, |_| None).0
                )
            })
            .collect();
        assert!(
            answers.windows(2).all(|w| w[0] == w[1]),
            "the arrival varied over one body: {answers:?}"
        );
    }
}

/// The plane never hands back a decision, an amount or a credential.
///
/// This is a source scan for the words a plane must not be able to say. It is coarse on purpose: a
/// plane that has started reasoning about money will name money.
#[test]
fn the_plane_names_no_money_and_no_decision() {
    let forbidden = [
        "nano_units",
        "nanounits",
        "unit_price",
        "price_micros",
        "charge(",
        "admit_decision",
        "allow(",
        "deny(",
        "credential_bytes",
        "secret_value",
        "auth_token_raw",
    ];
    let mut offenders = Vec::new();
    each_source(&mut |path, text| {
        for (n, line) in text.lines().enumerate() {
            if is_comment(line) || is_generated_include(line) {
                continue;
            }
            // A lint attribute is an instruction to the compiler, not a decision about a
            // request. It is the one shape here whose words overlap with the forbidden ones.
            let t = line.trim_start();
            if t.starts_with("#[") || t.starts_with("#![") {
                continue;
            }
            for name in forbidden {
                if line.contains(name) {
                    offenders.push(format!("{}:{}: {name}", path.display(), n + 1));
                }
            }
        }
    });
    assert!(
        offenders.is_empty(),
        "the plane names money or decisions: {offenders:?}"
    );
}

/// The macros that write a log line: the SDK's `diag_*!` and `tracing`'s own, which the SDK
/// captures into the envelope's log records just the same.
fn is_log_macro(name: &str) -> bool {
    name.starts_with("diag_")
        || ["trace", "debug", "info", "warn", "error", "event"].contains(&name)
}

/// THE PUSH TOKEN IS NEVER LOGGED (`BUSBAR-1.6.0.md` l.4882: the plane checks its own callback
/// correlation token, "never logged/audited"; the push route is audited nowhere, the door's own
/// cell): no log line the plane writes, in any of its sources, through a `diag_*!` or a `tracing`
/// macro, names the token, the field it rides in, or a value read from either.
#[test]
fn no_diagnostic_line_of_the_plane_carries_the_push_token() {
    let mut lines = 0;
    each_source(&mut |path, text| {
        for (bang, _) in text.match_indices("!(") {
            // The macro's name: the identifier right before `!(`, its path (`tracing::`) aside.
            let name_start = text[..bang]
                .rfind(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .map_or(0, |i| {
                    i + text[i..].chars().next().map_or(1, char::len_utf8)
                });
            if !is_log_macro(&text[name_start..bang]) {
                continue;
            }
            let start = name_start;
            let rest = &text[start..];
            let open = bang - start;
            // The call's arguments, to the parenthesis that closes them.
            let mut depth = 0usize;
            let close = rest[open + 1..]
                .char_indices()
                .find(|(_, c)| {
                    match c {
                        '(' => depth += 1,
                        ')' => depth -= 1,
                        _ => {}
                    }
                    depth == 0
                })
                .map_or(rest.len(), |(i, _)| open + 1 + i);
            let call = rest[open..close].to_ascii_lowercase();
            lines += 1;
            for word in ["token", "authorization", "presented", "claim"] {
                assert!(
                    !call.contains(word),
                    "{}: a diagnostic line names `{word}`: {call}",
                    path.display()
                );
            }
        }
    });
    assert!(lines > 0, "the scan read the plane's diagnostic lines");
}
