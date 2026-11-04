// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A safe witness reads only a borrowed, initialized String while its owner is still alive.

#[path = "string_custody_probe.rs"]
mod witness;
pub(crate) use witness::{assert_wiped, observe};
use witness::{Probe, SCOPE, SECRET};

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
    let mut projected = crate::plane_door::hook_view(&bytes)
        .map(|view| view.0)
        .expect("the projection reads");
    let doc: serde_json::Value = serde_json::from_slice(&projected).unwrap();
    assert_eq!(doc["arguments"], request()["params"]);
    projected.zeroize();
    assert_eq!(
        crate::plane_door::hook_view(&bytes).and_then(|view| view.2),
        None
    );
    probe.finished();

    let not_an_object = serde_json::to_vec(&serde_json::json!([{"credential":SECRET}])).unwrap();
    let probe = Probe::start();
    assert!(crate::plane_door::hook_view(&not_an_object)
        .map(|view| view.0)
        .is_none());
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
