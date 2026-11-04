// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Request and card values keep their ordinary borrowed or owned meaning.

use crate::binding::Binding;
use crate::relay::{From, HopRelay, Piece, PieceAnswer};

const BODY: &[u8] =
    br#"{"jsonrpc":"2.0","id":"1","method":"message/send","params":{"message":{"role":"user"}}}"#;
const URL: &str = "https://agent.example/a2a";

fn hop() -> HopRelay {
    let envelope: serde_json::Value = serde_json::from_slice(BODY).expect("the request is JSON");
    let mut relay = HopRelay::new(serde_json::json!("1"), "0.3");
    relay.bind(Binding::JsonRpc, &envelope);
    relay.name_backend("planner", URL);
    relay
}

fn relay_once(relay: &mut HopRelay) -> (PieceAnswer, PieceAnswer) {
    let attempt = relay.on_piece(Piece {
        from: From::Kernel(Some(URL)),
        bytes: &[],
        status: None,
        last: false,
    });
    let body = relay.on_piece(Piece {
        from: From::Caller,
        bytes: BODY,
        status: None,
        last: true,
    });
    (attempt, body)
}

#[test]
fn an_unrewritten_envelope_is_relayed_without_a_copy() {
    let (warm, warm_body) = relay_once(&mut hop());
    assert!(matches!(warm, PieceAnswer::Attempt(_)), "{warm:?}");
    assert_eq!(
        warm_body,
        PieceAnswer::ToFarEndLent,
        "with no task identifier to rewrite, the agent gets the caller's own bytes, lent"
    );
    let (attempt, body) = relay_once(&mut hop());
    let PieceAnswer::Attempt(attempt) = attempt else {
        panic!("an attempt: {attempt:?}");
    };
    assert_eq!((attempt.verb, attempt.target.as_str()), ("POST", "/a2a"));
    assert_eq!(body, PieceAnswer::ToFarEndLent);
}

#[test]
fn the_hook_view_keeps_projection_invocation_and_session_values() {
    let parts: Vec<serde_json::Value> = (0..1000)
        .map(|i| serde_json::json!({ "kind": "text", "text": format!("part {i}") }))
        .collect();
    let expected = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "message/send",
        "params": { "message": { "role": "user", "contextId": "ctx", "parts": parts } },
    });
    let envelope = serde_json::to_vec(&expected).unwrap();
    let (projection, invocation, session) =
        crate::plane_door::hook_view(&envelope).expect("a valid submission has a hook view");
    assert_eq!(session.as_deref(), Some("ctx"));
    assert_eq!(invocation.tool, "message/send");
    assert_eq!(invocation.arguments, expected["params"]);
    let projection: serde_json::Value = serde_json::from_slice(&projection).unwrap();
    assert_eq!(projection["tool"], invocation.tool);
    assert_eq!(projection["arguments"], invocation.arguments);
}

#[test]
fn reading_a_card_ignores_unmodelled_members() {
    let unmodelled: Vec<serde_json::Value> = (0..1000)
        .map(|i| serde_json::json!({ "note": format!("n{i}") }))
        .collect();
    let card = serde_json::json!({
        "name": "Planner", "description": "Plans.",
        "skills": [{ "id": "plan", "name": "Plan" }], "unmodelled": unmodelled,
    });
    let parsed = crate::a2a::agent_card::parse(&card).expect("known card fields parse");
    let expected = serde_json::json!({
        "name": "Planner", "description": "Plans.",
        "skills": [{ "id": "plan", "name": "Plan" }],
    });
    assert_eq!(parsed, crate::a2a::agent_card::parse(&expected).unwrap());
}
