// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Configuration judgments through the existing raw door, including its actual route snapshot.

use busbar_contract::abi::mechanism::call::{AbiStr, Blob, InHead, OutHead, Outcome, BLOB_JSON};
use busbar_contract::abi::mechanism::lifecycle::{slot, ReleaseIn, ValidateIn};
use busbar_contract::abi::plane::{Ops, PlaneOpenIn, PlaneOpenOut};
use busbar_test_kit::test_support::reply::{self, DiagCopy};
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

fn open(section: &Value) -> (Outcome, String, Vec<String>, Vec<DiagCopy>) {
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
    let called = unsafe {
        reply::call(
            ops().head.open.unwrap(),
            std::ptr::null_mut(),
            &input,
            output,
        )
    };
    let outcome = called.outcome;
    let output = called.out;
    let _instance = Instance(output.open.instance);
    assert!(output.open.err_len <= reason.len());
    let reason = String::from_utf8(reason[..output.open.err_len].to_vec()).unwrap();
    let claims = if outcome == Outcome::Ready {
        called
            .owned
            .expect("READY publishes a snapshot")
            .claims
            .into_iter()
            .map(|claim| claim.target)
            .collect()
    } else {
        Vec::new()
    };
    let mut diagnostics = called.envelope.diags;
    if output.open.head.lease != 0 {
        let input = ReleaseIn {
            head: InHead {
                size: std::mem::size_of::<ReleaseIn>() as u32,
                op: slot::RELEASE,
                ..zero()
            },
            lease: output.open.head.lease,
        };
        let output = OutHead {
            size: std::mem::size_of::<OutHead>() as u32,
            ..zero()
        };
        // SAFETY: the same live instance owns this reply's lease. Complete RELEASE frames
        // remain live, and reply::call already copied the snapshot and diagnostics.
        let released =
            unsafe { reply::call(ops().head.release.unwrap(), _instance.0, &input, output) };
        assert_eq!(released.outcome, Outcome::Ready);
        diagnostics.extend(released.envelope.diags);
    }
    (outcome, reason, claims, diagnostics)
}

fn validate(section: &Value) -> (Outcome, Vec<DiagCopy>) {
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
    let output = OutHead {
        size: std::mem::size_of::<OutHead>() as u32,
        ..zero()
    };
    // SAFETY: stateless VALIDATE receives its complete frames, live settings bytes and an
    // exclusive reason buffer for this synchronous call; it retains no instance.
    let called = unsafe {
        reply::call(
            ops().head.validate.unwrap(),
            std::ptr::null_mut(),
            &input,
            output,
        )
    };
    let mut diagnostics = called.envelope.diags;
    if called.out.lease != 0 {
        let input = ReleaseIn {
            head: InHead {
                size: std::mem::size_of::<ReleaseIn>() as u32,
                op: slot::RELEASE,
                ..zero()
            },
            lease: called.out.lease,
        };
        let output = OutHead {
            size: std::mem::size_of::<OutHead>() as u32,
            ..zero()
        };
        // SAFETY: stateless VALIDATE's returned lease belongs to the same door's unbound
        // call. Its exact RELEASE frames remain live after reply::call copied the payload.
        let released = unsafe {
            reply::call(
                ops().head.release.unwrap(),
                std::ptr::null_mut(),
                &input,
                output,
            )
        };
        assert_eq!(released.outcome, Outcome::Ready);
        diagnostics.extend(released.envelope.diags);
    }
    (called.outcome, diagnostics)
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
    let (outcome, reason, _, _) = open(&stated);
    assert_ne!(outcome, Outcome::Ready);
    assert!(
        reason.contains("egress_scopes") && reason.contains("not enforced"),
        "{reason}"
    );
    for name in ["a/b", "legal+eu", "..", "with space"] {
        let (outcome, reason, _, _) = open(&section(name, "https://agent.example/a2a"));
        assert_ne!(outcome, Outcome::Ready, "unroutable name {name}");
        assert!(reason.contains("path segment"), "{reason}");
    }
    let mut good = section("legal-eu_2.v~1", "https://agent.example/a2a");
    good["legal-eu_2.v~1"]["egress_scopes"] = json!([]);
    let (outcome, reason, claims, _) = open(&good);
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
    let mut events = Vec::new();
    for url in cases {
        let (outcome, reason, _, diagnostics) = open(&section("planner", url));
        events.extend(diagnostics);
        assert_ne!(outcome, Outcome::Ready);
        assert!(reason.contains("malformed"), "{reason}");
        for canary in ["USER_CANARY", "SECRET_CANARY", "TAIL_CANARY"] {
            assert!(!reason.contains(canary), "credential in refusal: {reason}");
        }
    }
    for event in events {
        for canary in ["USER_CANARY", "SECRET_CANARY", "TAIL_CANARY"] {
            assert!(
                !event.text.contains(canary),
                "credential in diagnostic: {event:?}"
            );
        }
    }
    let (outcome, reason, _, _) = open(&section("planner", "https://agent.example:99999/a2a"));
    assert_ne!(outcome, Outcome::Ready);
    assert!(
        reason.contains("malformed") && reason.contains("port"),
        "{reason}"
    );
    let (outcome, reason, _, _) = open(&section("planner", "ftp://agent.example/a2a"));
    assert_ne!(outcome, Outcome::Ready);
    assert!(
        reason.contains("must be an http:// or https:// endpoint"),
        "{reason}"
    );
    let (outcome, reason, _, _) = open(&section(
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
    let (outcome, mut events) = validate(&stated);
    assert_eq!(outcome, Outcome::Ready);
    let (outcome, reason, claims, diagnostics) = open(&stated);
    events.extend(diagnostics);
    assert_eq!(outcome, Outcome::Ready, "{reason}");
    assert!(claims.iter().any(|claim| claim == "/a2a/agents/planner/"));
    for _ in 0..2 {
        let (outcome, diagnostics) = validate(&stated);
        events.extend(diagnostics);
        assert_eq!(outcome, Outcome::Ready);
    }
    let warnings: Vec<_> = events
        .iter()
        .filter(|event| event.text.contains("BUSBAR-7051"))
        .collect();
    assert_eq!(
        warnings.len(),
        1,
        "one warning per successful section OPEN: {events:?}"
    );
    assert_eq!(
        warnings[0].severity,
        busbar_contract::abi::mechanism::call::SEVERITY_WARN
    );
    assert!(warnings[0].text.contains("protocol_version") && warnings[0].text.contains("ignored"));
    for event in events {
        let text = event.text;
        assert!(
            !text.contains("VERSION_VALUE_CANARY") && !text.contains("OTHER_VERSION_CANARY"),
            "{text}"
        );
    }

    let (outcome, _, _, mut events) = open(&section("planner", "https://agent.example/a2a"));
    assert_eq!(outcome, Outcome::Ready);
    let mut nonstring = section("planner", "https://agent.example/a2a");
    nonstring["planner"]["protocol_version"] = json!(7);
    let (outcome, _, _, diagnostics) = open(&nonstring);
    events.extend(diagnostics);
    assert_ne!(outcome, Outcome::Ready);
    let mut invalid = stated;
    invalid["planner"]["egress_scopes"] = json!(["billing"]);
    let (outcome, _, _, diagnostics) = open(&invalid);
    events.extend(diagnostics);
    assert_ne!(outcome, Outcome::Ready);
    assert!(
        events
            .iter()
            .all(|event| !event.text.contains("BUSBAR-7051")),
        "failed/unstated configurations must not warn as if opened"
    );
}
