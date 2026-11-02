// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What relaying an unchanged envelope is allowed to allocate, on the door's relay.

use crate::binding::Binding;
use crate::relay::{From, HopRelay, Piece, PieceAnswer};

use busbar_test_kit::alloc_counter::allocations_of;

/// One well-formed request of this protocol, carrying no task identifier to rewrite: the request

const BODY: &[u8] =
    br#"{"jsonrpc":"2.0","id":"1","method":"message/send","params":{"message":{"role":"user"}}}"#;

/// The agent's registered url.
const URL: &str = "https://agent.example/a2a";

/// COMMITTED BASELINE — the exact allocation count of ONE hop that rewrites nothing: the attempt's

const RELAY_ALLOCS: u64 = 2;

/// A JSON-RPC hop for [`BODY`], bound and named as the door binds and names one before its first

fn hop() -> HopRelay {
    let envelope: serde_json::Value = serde_json::from_slice(BODY).expect("the request is JSON");
    let mut relay = HopRelay::new(serde_json::json!("1"), "0.3");
    relay.bind(Binding::JsonRpc, &envelope);
    relay.name_backend("planner", URL);
    relay
}

/// The relay's loop for one attempt: the kernel's ATTEMPT, then the caller's body, `plant` more

fn relay_once(relay: &mut HopRelay, plant: usize) -> (PieceAnswer, PieceAnswer) {
    let attempt = relay.on_piece(Piece {
        from: From::Kernel(Some(URL)),
        bytes: &[],
        status: None,
        last: false,
    });
    for _ in 0..plant {
        std::hint::black_box(Box::new(0_u8));
    }
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
    let (warm, warm_body) = relay_once(&mut hop(), 0);
    assert!(matches!(warm, PieceAnswer::Attempt(_)), "{warm:?}");
    assert_eq!(
        warm_body,
        PieceAnswer::ToFarEndLent,
        "with no task identifier to rewrite, the agent gets the caller's own bytes, lent"
    );

    let mut relay = hop();
    let mut measured = None;
    let count = allocations_of(|| measured = Some(relay_once(&mut relay, 0)));
    println!("unrewritten relay allocations: {count}");
    let (attempt, body) = measured.expect("the hop ran");
    let PieceAnswer::Attempt(attempt) = attempt else {
        panic!("an attempt: {attempt:?}");
    };
    assert_eq!((attempt.verb, attempt.target.as_str()), ("POST", "/a2a"));
    assert_eq!(
        body,
        PieceAnswer::ToFarEndLent,
        "with no task identifier to rewrite, the agent gets the caller's own bytes, lent"
    );
    assert_eq!(
        count, RELAY_ALLOCS,
        "the relay allocated {count} times, not {RELAY_ALLOCS}: it is copying an envelope it \
         changes nothing about, or spelling a field it could borrow"
    );

    let mut relay = hop();
    let planted = allocations_of(|| {
        let _ = relay_once(&mut relay, 1);
    });
    assert_eq!(
        planted,
        RELAY_ALLOCS + 1,
        "the counter must see an allocation planted in the relay's loop"
    );
    assert_ne!(planted, RELAY_ALLOCS, "a planted allocation fails the pin");
}

/// G1-52: THE HOOK VIEW READS THE REQUEST ONCE: its projection, its invocation and its session are

#[test]
fn the_hook_view_parses_the_envelope_once() {
    let parts: Vec<serde_json::Value> = (0..1000)
        .map(|i| serde_json::json!({ "kind": "text", "text": format!("part {i}") }))
        .collect();
    let envelope = serde_json::to_vec(&serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "message/send",
        "params": { "message": { "role": "user", "contextId": "ctx", "parts": parts } },
    }))
    .unwrap();

    assert!(crate::plane_door::hook_view(&envelope).is_some());
    let parse = allocations_of(|| {
        std::hint::black_box(serde_json::from_slice::<serde_json::Value>(&envelope).unwrap());
    });
    let mut view = None;
    let count = allocations_of(|| view = crate::plane_door::hook_view(&envelope));
    println!("one parse: {parse} allocations; the hook view: {count}");
    assert!(view.is_some());
    assert!(
        count < 2 * parse,
        "the hook view allocated {count} times, one parse of the envelope {parse}: it parsed or \
         copied the request more than once"
    );
}

/// G1-10: reading a card's members borrows the card. A card carrying a large member busbar does

#[test]
fn reading_a_card_does_not_copy_it() {
    let unmodelled: Vec<serde_json::Value> = (0..1000)
        .map(|i| serde_json::json!({ "note": format!("n{i}") }))
        .collect();
    let card = serde_json::json!({
        "name": "Planner",
        "description": "Plans.",
        "skills": [{ "id": "plan", "name": "Plan" }],
        "unmodelled": unmodelled,
    });

    assert!(crate::a2a::agent_card::parse(&card).is_some());
    let mut parsed = None;
    let count = allocations_of(|| parsed = crate::a2a::agent_card::parse(&card));
    println!("card read allocations: {count}");
    assert!(parsed.is_some());
    assert!(
        count < 100,
        "reading the card allocated {count} times: it copied the card (1000 unmodelled members)"
    );
}

/// G1-16: A TASK HOP HOLDS ITS REQUEST ONCE: the envelope it opens the task from is the request it

#[test]
fn a_task_hop_does_not_copy_its_envelope() {
    let parts: Vec<serde_json::Value> = (0..1000)
        .map(|i| serde_json::json!({ "kind": "text", "text": format!("part {i}") }))
        .collect();
    let envelope = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "message/send",
        "params": { "message": { "role": "user", "parts": parts } },
    });

    drop(crate::plane_door::Hop::task(
        serde_json::json!(1),
        "1.0",
        envelope.clone(),
    ));
    let mut hop = None;
    let count = allocations_of(|| {
        hop = Some(crate::plane_door::Hop::task(
            serde_json::json!(1),
            "1.0",
            envelope,
        ));
    });
    println!("task hop allocations: {count}");
    assert!(hop.is_some());
    assert!(
        count < 100,
        "a task hop allocated {count} times: it copied its 1000-part envelope"
    );
}
