// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A safe witness reads only a borrowed, initialized String while its owner is still alive.

use std::cell::RefCell;

const SECRET: &str = "callback-credential-custody-canary";

#[derive(Default)]
struct Scope {
    active: bool,
    payloads: Vec<(usize, usize, bool)>,
}

thread_local! { static SCOPE: RefCell<Scope> = RefCell::new(Scope::default()); }

// The regression-only tree has no production wipe hook yet.
#[allow(dead_code)]
pub(crate) fn observe(after_wipe: bool, text: &str) {
    SCOPE.with(|scope| {
        let mut scope = scope.borrow_mut();
        if !scope.active {
            return;
        }
        let address = text.as_ptr() as usize;
        if !after_wipe && text == SECRET {
            scope.payloads.push((address, text.len(), false));
        } else if after_wipe {
            if let Some(payload) = scope
                .payloads
                .iter_mut()
                .rev()
                .find(|payload| payload.0 == address && !payload.2)
            {
                assert_eq!(
                    text.len(),
                    payload.1,
                    "the same initialized prefix is observed"
                );
                assert!(
                    text.as_bytes().iter().all(|byte| *byte == 0),
                    "credential was not wiped"
                );
                payload.2 = true;
            }
        }
    });
}

struct Probe;
impl Probe {
    fn start() -> Self {
        SCOPE.with(|scope| {
            let mut scope = scope.borrow_mut();
            assert!(!scope.active);
            *scope = Scope {
                active: true,
                ..Default::default()
            };
        });
        Self
    }

    fn finished(self) {
        SCOPE.with(|scope| {
            let scope = scope.borrow();
            assert!(
                !scope.payloads.is_empty(),
                "the owned credential String was not observed"
            );
            assert!(
                scope.payloads.iter().all(|payload| payload.2),
                "an observed credential escaped wiping"
            );
        });
    }
}
impl Drop for Probe {
    fn drop(&mut self) {
        SCOPE.with(|scope| *scope.borrow_mut() = Scope::default());
    }
}

/// Observe the credential allocations owned and released by one synchronous codec call.
pub(crate) fn assert_wiped(run: impl FnOnce()) {
    let probe = Probe::start();
    run();
    probe.finished();
}

fn request() -> serde_json::Value {
    serde_json::json!({"jsonrpc":"2.0", "id":7, "method":"SendMessage", "params": {
        "message":{"messageId":"m1", "role":"ROLE_USER", "parts":[]},
        "configuration":{"pushNotificationConfig":{"url":"https://callback.example", "authentication": {
            "scheme":"Bearer", "credentials":SECRET
        }}}
    }})
}

#[test]
fn retained_hop_request_wipes_its_initialized_credential_before_free() {
    let bytes = serde_json::to_vec(&request()).unwrap();
    let (disposition, parsed) = crate::agent_arrival::decide_and_read(&bytes, |name| {
        (name == crate::agent_arrival::H_VERSION).then_some("1.0")
    });
    assert!(matches!(
        disposition,
        crate::agent_arrival::AgentDisposition::Request { .. }
    ));
    let probe = Probe::start();
    let hop = crate::plane_door::Hop::of(serde_json::json!(7), "1.0", parsed);
    SCOPE.with(|scope| {
        assert!(
            scope.borrow().payloads.is_empty(),
            "a retained request is still live"
        )
    });
    drop(hop);
    probe.finished();
}

#[test]
fn relay_parameter_copies_and_clones_each_wipe_their_initialized_credential() {
    let request = request();
    let probe = Probe::start();
    let mut relay = crate::relay::HopRelay::new(serde_json::json!(7), "1.0");
    relay.bind(crate::binding::Binding::HttpJson, &request);
    let retained = relay.clone();
    drop(relay);
    drop(retained);
    probe.finished();
    assert_eq!(
        request["params"]["configuration"]["pushNotificationConfig"]["authentication"]
            ["credentials"],
        SECRET
    );
}

#[test]
fn request_object_keys_are_wiped_as_well_as_values() {
    let mut keys = serde_json::Map::new();
    keys.insert(SECRET.to_string(), serde_json::json!("extension"));
    let probe = Probe::start();
    let hop = crate::plane_door::Hop::of(
        serde_json::json!(7),
        "1.0",
        Some(serde_json::Value::Object(keys)),
    );
    drop(hop);
    probe.finished();
}

#[test]
fn hook_projection_and_session_reads_wipe_their_temporary_request_trees() {
    use zeroize::Zeroize;
    let bytes = serde_json::to_vec(&request()).unwrap();
    let probe = Probe::start();
    let mut projected = crate::plane_door::projection(&bytes).expect("the projection reads");
    let doc: serde_json::Value = serde_json::from_slice(&projected).unwrap();
    assert_eq!(doc["arguments"], request()["params"]);
    projected.zeroize();
    assert_eq!(crate::plane_door::context_session(&bytes), None);
    probe.finished();

    let not_an_object = serde_json::to_vec(&serde_json::json!([{"credential":SECRET}])).unwrap();
    let probe = Probe::start();
    assert!(crate::plane_door::projection(&not_an_object).is_none());
    probe.finished();
}

#[test]
fn replacement_params_wipe_superseded_candidates_and_transfer_only_the_final_tree() {
    use zeroize::Zeroize;
    let bytes = serde_json::to_vec(&request()).unwrap();
    let rewrite = serde_json::to_vec(&serde_json::json!({"messages":[
        {"content":{"credential":SECRET, "discarded":true}},
        {"content":{"credential":SECRET, "kept":true}}
    ]}))
    .unwrap();
    let probe = Probe::start();
    let params = crate::plane_door::rewritten_params(&rewrite)
        .unwrap()
        .unwrap();
    assert_eq!(params["kept"], true);
    assert!(params.get("discarded").is_none());
    let (changed, mut serialized) = crate::plane_door::with_params(&bytes, params).unwrap();
    assert_eq!(changed["params"]["credential"], SECRET);
    serialized.zeroize();
    let hop = crate::plane_door::Hop::of(serde_json::json!(7), "1.0", Some(changed));
    drop(hop);
    probe.finished();

    let probe = Probe::start();
    assert!(
        crate::plane_door::with_params(b"[]", serde_json::json!({"credential":SECRET})).is_none()
    );
    probe.finished();
}
