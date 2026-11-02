// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Configuration judgments through the existing raw door, including its actual route snapshot.

#[path = "../src/tests/capture.rs"]
mod capture;

use busbar_contract::abi::mechanism::call::{AbiStr, Blob, InHead, OutHead, Outcome, BLOB_JSON};
use busbar_contract::abi::mechanism::lifecycle::{slot, ValidateIn};
use busbar_contract::abi::plane::{Ops, PlaneOpenIn, PlaneOpenOut};
use serde_json::{json, Value};
use std::ffi::c_void;

fn zero<T>() -> T {
    // SAFETY: only plain ABI frames, for which zero is the absent/default representation.
    unsafe { std::mem::zeroed() }
}

fn blob(bytes: &[u8]) -> Blob {
    // SAFETY: the caller keeps bytes alive for the synchronous door crossing.
    unsafe { Blob::from_raw_parts(bytes.as_ptr(), bytes.len(), BLOB_JSON, 0) }
}

fn ops() -> &'static Ops {
    // SAFETY: the public door is the plane kind's static table.
    unsafe { &*(*busbar_plane_a2a::door()).ops().cast::<Ops>() }
}

struct Instance(*mut c_void);

impl Drop for Instance {
    fn drop(&mut self) {
        if self.0.is_null() {
            return;
        }
        let input = InHead {
            size: std::mem::size_of::<InHead>() as u32,
            op: slot::CLOSE,
            ..zero()
        };
        let mut output = OutHead {
            size: std::mem::size_of::<OutHead>() as u32,
            ..zero()
        };
        // SAFETY: this unique Instance owns the nonnull pointer returned by this door's OPEN.
        // Drop calls CLOSE once; the complete head frames remain live for the call.
        unsafe {
            ops().head.close.unwrap()(
                self.0,
                std::ptr::from_ref(&input).cast(),
                std::ptr::from_mut(&mut output).cast(),
            );
        }
    }
}

fn open(section: &Value) -> (Outcome, String, Vec<String>) {
    let bytes = serde_json::to_vec(section).unwrap();
    let mut reason = [0u8; 2048];
    let mut input: PlaneOpenIn = zero();
    input.open.head = InHead {
        size: std::mem::size_of::<PlaneOpenIn>() as u32,
        op: slot::OPEN,
        ..zero()
    };
    input.open.settings = blob(&bytes);
    input.open.generation = 1;
    input.open.err_buf = reason.as_mut_ptr();
    input.open.err_cap = reason.len();
    // SAFETY: the public URL is static and the door copies it while opening the instance.
    input.public_url = unsafe {
        AbiStr::from_raw_parts(b"https://gw.example".as_ptr(), b"https://gw.example".len())
    };
    let mut output: PlaneOpenOut = zero();
    output.open.head.size = std::mem::size_of::<PlaneOpenOut>() as u32;
    // SAFETY: OPEN receives complete PlaneOpenIn/Out frames, live settings and static URL
    // bytes, and an exclusive reason buffer. Instance below owns the returned pointer.
    let outcome = unsafe {
        ops().head.open.unwrap()(
            std::ptr::null_mut(),
            std::ptr::from_ref(&input).cast(),
            std::ptr::from_mut(&mut output).cast(),
        )
    }
    .outcome();
    let _instance = Instance(output.open.instance);
    assert!(output.open.err_len <= reason.len());
    let reason = String::from_utf8(reason[..output.open.err_len].to_vec()).unwrap();
    let claims = if outcome == Outcome::Ready {
        assert!(!output.snapshot.is_null());
        // SAFETY: READY publishes a snapshot that remains live until this instance closes.
        let snapshot = unsafe { &*output.snapshot };
        if snapshot.claims_len == 0 {
            Vec::new()
        } else {
            // SAFETY: the snapshot owns claims_len entries and each target string while live.
            unsafe { std::slice::from_raw_parts(snapshot.claims, snapshot.claims_len) }
                .iter()
                .map(|claim| {
                    // SAFETY: each target belongs to the live generation's snapshot above.
                    unsafe { claim.target.as_str() }.unwrap().to_owned()
                })
                .collect()
        }
    } else {
        Vec::new()
    };
    (outcome, reason, claims)
}

fn validate(section: &Value) -> Outcome {
    let bytes = serde_json::to_vec(section).unwrap();
    let mut reason = [0u8; 2048];
    let input = ValidateIn {
        head: InHead {
            size: std::mem::size_of::<ValidateIn>() as u32,
            op: slot::VALIDATE,
            ..zero()
        },
        settings: blob(&bytes),
        err_buf: reason.as_mut_ptr(),
        err_cap: reason.len(),
    };
    let mut output = OutHead {
        size: std::mem::size_of::<OutHead>() as u32,
        ..zero()
    };
    // SAFETY: stateless VALIDATE receives its complete frames, live settings bytes and an
    // exclusive reason buffer for this synchronous call; it retains no instance.
    unsafe {
        ops().head.validate.unwrap()(
            std::ptr::null_mut(),
            std::ptr::from_ref(&input).cast(),
            std::ptr::from_mut(&mut output).cast(),
        )
    }
    .outcome()
}

fn section(name: &str, url: &str) -> Value {
    let mut section = serde_json::Map::new();
    section.insert(
        name.to_owned(),
        json!({"url": url, "pin": {"mechanism": "unpinned"}}),
    );
    Value::Object(section)
}

#[test]
fn open_refuses_inert_policy_and_unroutable_names_but_publishes_valid_agent_claims() {
    let mut stated = section("planner", "https://agent.example/a2a");
    stated["planner"]["egress_scopes"] = json!(["billing"]);
    let (outcome, reason, _) = open(&stated);
    assert_ne!(outcome, Outcome::Ready);
    assert!(
        reason.contains("egress_scopes") && reason.contains("not enforced"),
        "{reason}"
    );
    for name in ["a/b", "legal+eu", "..", "with space"] {
        let (outcome, reason, _) = open(&section(name, "https://agent.example/a2a"));
        assert_ne!(outcome, Outcome::Ready, "unroutable name {name}");
        assert!(reason.contains("path segment"), "{reason}");
    }
    let mut good = section("legal-eu_2.v~1", "https://agent.example/a2a");
    good["legal-eu_2.v~1"]["egress_scopes"] = json!([]);
    let (outcome, reason, claims) = open(&good);
    assert_eq!(outcome, Outcome::Ready, "{reason}");
    assert!(
        claims
            .iter()
            .any(|claim| claim == "/a2a/agents/legal-eu_2.v~1/"),
        "{claims:?}"
    );
}

#[test]
fn open_malformed_url_refusals_omit_all_raw_credential_fragments() {
    let cases = [
        "https://USER_CANARY:prefix@SECRET_CANARY:99999#TAIL_CANARY@host/a2a",
        "https://USER_CANARY:SECRET_CANARY#TAIL_CANARY@host/a2a",
        "https://USER_CANARY:SECRET_CANARY?TAIL_CANARY@host/a2a",
        "https://USER_CANARY:SECRET_CANARY/TAIL_CANARY@host/a2a",
        "https://USER_CANARY:SECRET_CANARY@host:99999/a2a",
    ];
    let (sent, events) = std::sync::mpsc::channel();
    tracing::subscriber::with_default(capture::Capture(sent), || {
        for url in cases {
            let (outcome, reason, _) = open(&section("planner", url));
            assert_ne!(outcome, Outcome::Ready);
            assert!(reason.contains("malformed"), "{reason}");
            for canary in ["USER_CANARY", "SECRET_CANARY", "TAIL_CANARY"] {
                assert!(!reason.contains(canary), "credential in refusal: {reason}");
            }
        }
    });
    for (_, event) in events.try_iter() {
        for canary in ["USER_CANARY", "SECRET_CANARY", "TAIL_CANARY"] {
            assert!(!event.contains(canary), "credential in diagnostic: {event}");
        }
    }
    let (outcome, reason, _) = open(&section("planner", "https://agent.example:99999/a2a"));
    assert_ne!(outcome, Outcome::Ready);
    assert!(
        reason.contains("malformed") && reason.contains("port"),
        "{reason}"
    );
    let (outcome, reason, _) = open(&section("planner", "ftp://agent.example/a2a"));
    assert_ne!(outcome, Outcome::Ready);
    assert!(
        reason.contains("must be an http:// or https:// endpoint"),
        "{reason}"
    );
    let (outcome, reason, _) = open(&section(
        "planner",
        "https://alice:SECRET_CANARY@agent.example/a2a",
    ));
    assert_ne!(outcome, Outcome::Ready);
    assert!(
        reason.contains("userinfo") && !reason.contains("SECRET_CANARY"),
        "{reason}"
    );
}

#[test]
fn ignored_protocol_version_warns_once_at_open_without_echoing_its_value() {
    let mut stated = section("planner", "https://agent.example/a2a");
    stated["planner"]["protocol_version"] = json!("VERSION_VALUE_CANARY");
    stated["worker"] = json!({"url": "https://worker.example/a2a", "pin": {"mechanism": "unpinned"}, "protocol_version": "OTHER_VERSION_CANARY"});
    let (sent, events) = std::sync::mpsc::channel();
    tracing::subscriber::with_default(capture::Capture(sent), || {
        assert_eq!(validate(&stated), Outcome::Ready);
        let (outcome, reason, claims) = open(&stated);
        assert_eq!(outcome, Outcome::Ready, "{reason}");
        assert!(claims.iter().any(|claim| claim == "/a2a/agents/planner/"));
        assert_eq!(validate(&stated), Outcome::Ready);
        assert_eq!(validate(&stated), Outcome::Ready);
    });
    let events: Vec<_> = events.try_iter().collect();
    let warnings: Vec<_> = events
        .iter()
        .filter(|(_, text)| text.contains("BUSBAR-7051"))
        .collect();
    assert_eq!(
        warnings.len(),
        1,
        "one warning per successful section OPEN: {events:?}"
    );
    assert_eq!(warnings[0].0, tracing::Level::WARN);
    assert!(warnings[0].1.contains("protocol_version") && warnings[0].1.contains("ignored"));
    for (_, text) in events {
        assert!(
            !text.contains("VERSION_VALUE_CANARY") && !text.contains("OTHER_VERSION_CANARY"),
            "{text}"
        );
    }

    let (sent, events) = std::sync::mpsc::channel();
    tracing::subscriber::with_default(capture::Capture(sent), || {
        assert_eq!(
            open(&section("planner", "https://agent.example/a2a")).0,
            Outcome::Ready
        );
        let mut nonstring = section("planner", "https://agent.example/a2a");
        nonstring["planner"]["protocol_version"] = json!(7);
        assert_ne!(open(&nonstring).0, Outcome::Ready);
        let mut invalid = stated;
        invalid["planner"]["egress_scopes"] = json!(["billing"]);
        assert_ne!(open(&invalid).0, Outcome::Ready);
    });
    assert!(
        events
            .try_iter()
            .all(|(_, text)| !text.contains("BUSBAR-7051")),
        "failed/unstated configurations must not warn as if opened"
    );
}
