// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Configuration judgments through the actual production loader and published A2A macro door.

use busbar_contract::abi::mechanism::call::{AbiStr, Blob, Outcome, BLOB_JSON};
use busbar_contract::abi::mechanism::lifecycle::{slot, ReleaseIn, ValidateIn};
use busbar_contract::abi::plane::{PlaneOpenIn, PlaneOpenOut};
use busbar_contract::abi::sdk::test_support::zeroed;
use busbar_plugin_loader::dispatch::kinds::plane::Plane;
use busbar_plugin_loader::dispatch::{
    in_head, load_linked, out_head, Bind, ConnTable, Diagnostic, DispatchConfig, Dispatcher,
    Dropped, EnvelopeSink, Frame, LinkedRow, Metric, Plugin,
};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

#[derive(Debug)]
struct ConfigDiagnostic {
    severity: u8,
    text: String,
}

#[derive(Default)]
struct ConfigEvents {
    diagnostics: Mutex<Vec<ConfigDiagnostic>>,
    dropped: AtomicBool,
}

impl EnvelopeSink for ConfigEvents {
    fn metric(&self, _: Metric<'_>) {}

    fn diag(&self, diagnostic: Diagnostic<'_>) {
        // The real loader validates and lends this envelope to its sink before lease release.
        self.diagnostics.lock().unwrap().push(ConfigDiagnostic {
            severity: diagnostic.severity,
            text: String::from_utf8(diagnostic.text.to_vec()).unwrap(),
        });
    }

    fn dropped(&self, _: Dropped) {
        self.dropped.store(true, Ordering::SeqCst);
    }
}

impl ConfigEvents {
    fn take(&self) -> Vec<ConfigDiagnostic> {
        assert!(
            !self.dropped.load(Ordering::SeqCst),
            "configuration diagnostics were not dropped"
        );
        std::mem::take(&mut *self.diagnostics.lock().unwrap())
    }
}

fn product() -> (Dispatcher, Plugin<Plane>, Arc<ConfigEvents>) {
    static NEXT_INSTANCE: AtomicU64 = AtomicU64::new(1);
    let dispatcher = Dispatcher::new(DispatchConfig::default());
    let sink = Arc::new(ConfigEvents::default());
    let row = LinkedRow::of_macro(busbar_plane_a2a::MACRO_DOOR).unwrap();
    let plugin = load_linked::<Plane>(
        &row,
        Bind {
            instance: format!(
                "a2a-config-lifecycle-{}",
                NEXT_INSTANCE.fetch_add(1, Ordering::SeqCst)
            )
            .into(),
            max_inflight_cap: 64,
            sink: sink.clone(),
            dispatcher: dispatcher.adopter(),
            // Configuration checks publish facts without opening a connection to serve traffic.
            conns: ConnTable::Probe,
        },
    )
    .unwrap();
    (dispatcher, plugin, sink)
}

fn blob(bytes: &[u8]) -> Blob {
    // SAFETY: the caller retains these owned bytes through the synchronous real loader crossing.
    unsafe { Blob::from_raw_parts(bytes.as_ptr(), bytes.len(), BLOB_JSON, 0) }
}

fn release(plugin: &Plugin<Plane>, lease: u64) -> Outcome {
    let mut frame = Box::new(Frame::new(
        ReleaseIn {
            head: in_head(),
            lease,
        },
        out_head(),
    ));
    let outcome = plugin.call(slot::RELEASE, &mut frame).outcome;
    if outcome == Outcome::Pending {
        // The caller retains the product as well before failing; do not free this pending frame.
        std::mem::forget(frame);
    }
    outcome
}

fn close(plugin: &Plugin<Plane>) -> Outcome {
    let mut frame = Box::new(Frame::new(in_head(), out_head()));
    let outcome = plugin.call(slot::CLOSE, &mut frame).outcome;
    if outcome == Outcome::Pending {
        std::mem::forget(frame);
    }
    outcome
}

fn open(section: &Value) -> (Outcome, String, Vec<String>, Vec<ConfigDiagnostic>) {
    let (dispatcher, plugin, sink) = product();
    let bytes = serde_json::to_vec(section).unwrap().into_boxed_slice();
    let mut reason = Box::new([0u8; 2048]);
    let mut frame: Box<Frame<PlaneOpenIn, PlaneOpenOut>> = Box::new(Frame::new(zeroed(), zeroed()));
    frame.input.open.head = in_head();
    frame.out.open.head = out_head();
    frame.input.open.settings = blob(&bytes);
    frame.input.open.generation = 1;
    frame.input.open.err_buf = reason.as_mut_ptr();
    frame.input.open.err_cap = reason.len();
    // SAFETY: static URL bytes remain live through OPEN; the actual plane copies them.
    frame.input.public_url = unsafe {
        AbiStr::from_raw_parts(b"https://gw.example".as_ptr(), b"https://gw.example".len())
    };
    let (called, snapshot) = plugin.open(&mut frame);
    if called.outcome == Outcome::Pending {
        // An unexpected asynchronous OPEN cannot authorize freeing any original loan owner.
        std::mem::forget((dispatcher, plugin, frame, bytes, reason));
        panic!("configuration OPEN must complete synchronously");
    }
    if called.lease != 0 && release(&plugin, called.lease) != Outcome::Ready {
        std::mem::forget((dispatcher, plugin, frame, bytes, reason));
        panic!("the actual OPEN reply lease must release synchronously");
    }
    if plugin.is_open() && close(&plugin) != Outcome::Ready {
        std::mem::forget((dispatcher, plugin, frame, bytes, reason));
        panic!("the actual configuration instance must close synchronously");
    }
    assert!(
        !plugin.is_open(),
        "the opened configuration instance is closed exactly once"
    );
    assert!(frame.out.open.err_len <= reason.len());
    let reason = String::from_utf8(reason[..frame.out.open.err_len].to_vec()).unwrap();
    let claims = if called.outcome == Outcome::Ready {
        snapshot
            .expect("READY publishes a snapshot")
            .claims
            .into_iter()
            .map(|claim| claim.target)
            .collect()
    } else {
        Vec::new()
    };
    (called.outcome, reason, claims, sink.take())
}

fn validate(section: &Value) -> (Outcome, Vec<ConfigDiagnostic>) {
    let (dispatcher, plugin, sink) = product();
    let bytes = serde_json::to_vec(section).unwrap().into_boxed_slice();
    let mut reason = Box::new([0u8; 2048]);
    let mut frame = Box::new(Frame::new(
        ValidateIn {
            head: in_head(),
            settings: blob(&bytes),
            err_buf: reason.as_mut_ptr(),
            err_cap: reason.len(),
        },
        out_head(),
    ));
    let called = plugin.call(slot::VALIDATE, &mut frame);
    if called.outcome == Outcome::Pending {
        std::mem::forget((dispatcher, plugin, frame, bytes, reason));
        panic!("configuration VALIDATE must complete synchronously");
    }
    if called.lease != 0 && release(&plugin, called.lease) != Outcome::Ready {
        std::mem::forget((dispatcher, plugin, frame, bytes, reason));
        panic!("the actual VALIDATE reply lease must release synchronously");
    }
    assert!(
        !plugin.is_open(),
        "stateless validation never opens an instance"
    );
    (called.outcome, sink.take())
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
