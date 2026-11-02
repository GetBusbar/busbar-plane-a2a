//! The plane, driven over the vocabulary the conformance rigs actually send.

use crate::agent_arrival::{self, AgentDisposition};
use crate::ops;

/// The rig's own vocabulary table, read out of the file the rig imports it from.

fn rig_vocabulary(table: &str) -> Vec<(String, String)> {
    let rig =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../testing/a2a-supplement");
    let source = std::fs::read_to_string(rig.join("a2asup/transport.py")).expect(
        "the rig's vocabulary table is readable (testing/a2a-supplement/a2asup/transport.py)",
    );
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

fn decode(body: &[u8]) -> Result<(ops::MethodRow, serde_json::Value), String> {
    match agent_arrival::decide_and_read(body, |_| None).0 {
        AgentDisposition::Request { row, id, .. } => Ok((*row, id)),
        other => Err(format!("{other:?}")),
    }
}

/// Every method the rig's later-revision table names decodes to a declared class.
#[test]
fn every_method_of_the_later_vocabulary_decodes() {
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

/// Accepted methods handled locally retain their declared class and caller correlation at arrival.
#[test]
fn accepted_local_methods_keep_their_class_and_correlation() {
    let local: Vec<_> = ops::METHODS
        .iter()
        .filter(|row| crate::local::verb_of(row.method).is_some())
        .collect();
    assert!(!local.is_empty(), "no accepted local method was exercised");
    for expected in local {
        let (actual, correlation) = decode(&request("1", expected.method))
            .unwrap_or_else(|e| panic!("{} did not decode: {e}", expected.method));
        assert_eq!(actual, *expected);
        assert_eq!(correlation, 1, "{} lost its identifier", expected.method);
    }
}
