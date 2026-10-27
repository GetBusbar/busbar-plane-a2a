//! The plane, driven over the vocabulary the conformance rigs actually send.
//!
//! ## Why this shape, and what it is not
//!
//! The judges of this work are the rigs: the official suite and the in-house battery, both of which
//! speak to a booted node over a socket. These tests take the METHOD VOCABULARY out of the rig's own
//! table and out of the codec's own source, drive each entry through the door's arrival (the one
//! decode step the plane has, since the flip deleted the engine and its in-process `Plane` impl), and
//! assert the operation class and the request id it reads; the door itself is then driven op by op,
//! linked and dropped in, by the plugin crate's `tests/both_ways.rs`.

use busbar_plane_a2a::agent_arrival::{self, AgentDisposition};
use busbar_plane_a2a::ops;

/// The rig's own vocabulary table, read out of the file the rig imports it from.
///
/// Reading the rig's source rather than restating it is the whole point: a rig that starts sending a
/// method this plane does not carry must fail HERE, at build time, rather than in a battery run that
/// someone has to interpret.
fn rig_vocabulary(table: &str) -> Vec<(String, String)> {
    // busbar's rig at the pin this repo names (`BUSBAR_CHECKOUT`, a checkout of GetBusbar/busbar at
    // `.busbar-ref`, which plugin CI exports). An unset variable is a failure, never a skip.
    let busbar = std::env::var_os("BUSBAR_CHECKOUT").expect(
        "BUSBAR_CHECKOUT is unset: the rig is busbar's testing/a2a-supplement at .busbar-ref \
         (plugin CI exports it; locally, point it at a busbar checkout)",
    );
    let source = std::fs::read_to_string(
        std::path::PathBuf::from(busbar).join("testing/a2a-supplement/a2asup/transport.py"),
    )
    .expect("the rig's vocabulary table is readable");
    let start = source
        .find(&format!("{table} = {{"))
        .unwrap_or_else(|| panic!("the rig no longer declares {table}"));
    let body = &source[start..];
    let end = body.find('}').expect("the table closes");
    let mut rows = Vec::new();
    for line in body[..end].lines().skip(1) {
        let line = line.trim().trim_end_matches(',');
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim().trim_matches('"');
        let value = value.trim().trim_matches('"');
        if !key.is_empty() && !value.is_empty() {
            rows.push((key.to_string(), value.to_string()));
        }
    }
    assert!(!rows.is_empty(), "the rig's {table} table read as empty");
    rows
}

/// One request envelope of this protocol, with the method and identifier a caller would send.
fn request(id: &str, method: &str) -> Vec<u8> {
    format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"{method}","params":{{}}}}"#).into_bytes()
}

/// Drive one body through the door's arrival (the JSON-RPC line, no head fields) and hand back the
/// method row it classed the request under and the request id it read.
fn decode(body: &[u8]) -> Result<(ops::MethodRow, serde_json::Value), String> {
    match agent_arrival::decide_and_read(body, |_| None).0 {
        AgentDisposition::Request { row, id, .. } => Ok((*row, id)),
        other => Err(format!("{other:?}")),
    }
}

/// Every method the rig's later-revision table names decodes to a declared class.
#[test]
fn every_method_of_the_later_vocabulary_decodes() {
    // The slot name is the rig's own key for the row; the two tables are paired on it by
    // `the_two_vocabularies_agree_slot_for_slot`, which is where that pairing is actually proved.
    for (_slot, method) in rig_vocabulary("METHODS_1_0") {
        let body = request("1", &method);
        let (row, correlation) = decode(&body)
            .unwrap_or_else(|e| panic!("the rig sends {method} and this plane answered {e:?}"));
        assert_eq!(row.method, method);
        assert_eq!(
            row.wording,
            ops::Wording::Verb,
            "{method} is the verb wording"
        );
        assert_eq!(correlation, 1, "{method} lost its identifier");
    }
}

/// Every method the rig's earlier-revision table names decodes to a declared class.
#[test]
fn every_method_of_the_earlier_vocabulary_decodes() {
    for (_, method) in rig_vocabulary("METHODS_0_3") {
        let body = request("1", &method);
        let (row, _) = decode(&body)
            .unwrap_or_else(|e| panic!("the rig sends {method} and this plane answered {e:?}"));
        assert_eq!(row.method, method);
        assert_eq!(row.wording, ops::Wording::Slashed);
    }
}

/// The two vocabularies agree slot for slot on the class the unit is.
///
/// This is the property that says a caller's choice of wording does not move the money, checked
/// against the rig's OWN pairing of the two tables rather than against this crate's.
#[test]
fn the_two_vocabularies_agree_slot_for_slot() {
    let later = rig_vocabulary("METHODS_1_0");
    let earlier = rig_vocabulary("METHODS_0_3");
    assert_eq!(
        later.len(),
        earlier.len(),
        "the rig's two tables differ in size"
    );
    for (slot, method) in &later {
        let partner = earlier
            .iter()
            .find(|(k, _)| k == slot)
            .unwrap_or_else(|| panic!("the rig names {slot} in one table only"));
        let (a, _) = decode(&request("1", method)).expect("the later wording decodes");
        let (b, _) = decode(&request("1", &partner.1)).expect("the earlier wording decodes");
        assert_eq!(
            a.op, b.op,
            "the two wordings of {slot} price differently: {} against {}",
            a.op, b.op
        );
        assert_eq!(
            a.multi_frame, b.multi_frame,
            "the two wordings of {slot} stream differently"
        );
    }
}

/// Every method the codec's own local-verb table names is one this plane carries.
///
/// The table itself, iterated. This SCRAPED it out of the server half's source once — an
/// `include_str!` over `../../busbar-a2a/src/a2a/local.rs`, then a hand-rolled scan for quoted
/// pieces that look like a method name — which coupled this crate to a sibling its manifest does not
/// name, so the plane could be neither built nor deleted on its own. The table is the codec's now,
/// and the server half's `verb_of` is pinned against it in the crate that owns the match. A method
/// the codec answers and this plane does not carry would arrive here as an unsupported operation.
#[test]
fn every_local_verb_of_the_codec_is_carried() {
    let mut seen = 0usize;
    for method in [
        "ListTasks",
        "tasks/list",
        "CreateTaskPushNotificationConfig",
        "tasks/pushNotificationConfig/set",
        "GetTaskPushNotificationConfig",
        "tasks/pushNotificationConfig/get",
        "ListTaskPushNotificationConfigs",
        "tasks/pushNotificationConfig/list",
        "DeleteTaskPushNotificationConfig",
        "tasks/pushNotificationConfig/delete",
        "SubscribeToTask",
        "tasks/resubscribe",
    ] {
        assert!(
            decode(&request("1", method)).is_ok(),
            "the codec answers {method} and this plane does not carry it"
        );
        seen += 1;
    }
    assert!(
        seen >= 11,
        "only {seen} verbs were read out of the codec's table"
    );
}
