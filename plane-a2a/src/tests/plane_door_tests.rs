// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The door's own glue over the relay: what a unit's line does to the caller's answer.

#[path = "../../../testing/settings/integer_token.rs"]
mod settings_profile;

use super::*;

#[path = "task_door_listing_cases.rs"]
mod task_door_listing_cases;
use serde_json::{json, Value};

fn reply(status: u32, doc: &Value) -> PieceAnswer {
    PieceAnswer::ToCaller(relay::RelayReply {
        status,
        content_type: crate::agent_arrival::JSON_MEDIA_TYPE,
        body: serde_json::to_vec(doc).unwrap(),
    })
}

fn body_of(answer: PieceAnswer) -> (u32, Value) {
    match answer {
        PieceAnswer::ToCaller(r) => (r.status, serde_json::from_slice(&r.body).unwrap()),
        other => panic!("not the caller's answer: {other:?}"),
    }
}

/// On the HTTP+JSON line a relayed answer leaves as its bare `result` (A2A section 11.3), and a
/// refusal as the AIP-193 document at its own status, as the engine re-frames them.
#[test]
fn the_target_line_answers_the_bare_result_and_an_aip193_refusal() {
    let task =
        json!({ "id": "a2a-planner-01", "contextId": "c", "status": { "state": "completed" } });
    let ok = json!({ "jsonrpc": "2.0", "id": 7, "result": task.clone() });
    assert_eq!(body_of(for_line(reply(200, &ok), true)), (200, task));

    let refused = json!({
        "jsonrpc": "2.0", "id": 7,
        "error": { "code": -32001, "message": "no task with that id is open for this caller" },
    });
    let (status, doc) = body_of(for_line(reply(404, &refused), true));
    assert_eq!(status, 404);
    assert_eq!(doc, crate::agent_arrival::aip193(404, &refused["error"]));
}

/// On the JSON-RPC line the answer is the relay's, byte for byte; and a piece that is not the
/// caller's whole answer is never touched, on either line.
#[test]
fn the_document_line_and_a_partial_answer_are_left_alone() {
    let ok = json!({ "jsonrpc": "2.0", "id": 7, "result": { "kind": "task" } });
    assert_eq!(for_line(reply(200, &ok), false), reply(200, &ok));
    let to_far = PieceAnswer::ToFarEnd(b"{}".to_vec().into());
    assert_eq!(for_line(to_far.clone(), true), to_far);
    assert_eq!(for_line(PieceAnswer::Nothing, true), PieceAnswer::Nothing);
}

#[test]
fn an_outbox_keeps_sensitive_bytes_in_order_across_a_short_write_and_replacement() {
    let first = br#"{"credential":"first-secret"}"#;
    let second = br#"{"credential":"second-secret"}"#;
    let mut outbox =
        Outbox::of(PieceAnswer::ToFarEnd(first.to_vec().into())).expect("first answer");
    let cut = first.len() / 2;
    let mut emitted = Vec::new();
    assert_eq!(
        outbox.drain(|bytes| {
            emitted.extend_from_slice(&bytes[..cut]);
            cut
        }),
        cut
    );
    assert_eq!(outbox.at, cut);
    assert_eq!(
        outbox.drain(|bytes| {
            emitted.extend_from_slice(bytes);
            bytes.len()
        }),
        first.len() - cut
    );
    assert_eq!(outbox.at, first.len());
    assert_eq!(emitted, first, "a short write preserves the exact suffix");
    outbox = Outbox::of(PieceAnswer::ToFarEnd(second.to_vec().into())).expect("next answer");
    assert_eq!(
        outbox.bytes.as_slice(),
        second,
        "replacement keeps the new body"
    );
}

#[test]
fn cancelling_and_replacing_an_outbox_wipes_its_initialized_body_and_queued_messages() {
    use crate::tests::raw_custody_probe::{assert_wiped, SECRET};
    assert_wiped(|| {
        let mut outbox = Outbox::of(PieceAnswer::ToFarEnd(SECRET.to_vec().into())).unwrap();
        outbox.queue.push_back(SECRET.to_vec().into());
        outbox = Outbox::of(PieceAnswer::Nothing).unwrap();
        assert!(outbox.bytes.is_empty());
    });
}

/// On the HTTP+JSON line each event of an answer in events leaves as its bare result.
#[test]
fn the_target_line_answers_each_event_as_its_bare_result() {
    let event = b"data: {\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{\"kind\":\"task\"}}\n\n".to_vec();
    let part = |body: Vec<u8>| {
        PieceAnswer::Part(relay::Part {
            head: true,
            body,
            last: false,
        })
    };
    assert_eq!(
        for_line(part(event.clone()), true),
        part(b"data: {\"kind\":\"task\"}\n\n".to_vec())
    );
    assert_eq!(for_line(part(event.clone()), false), part(event));
}

fn request(method: &str) -> AgentDisposition {
    AgentDisposition::Request {
        row: crate::ops::row_for(method).expect("a listed method"),
        id: json!(7),
        version: "1.0",
    }
}

fn envelope(method: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": 7, "method": method, "params": { "id": "t1" } })
}

/// A request whose answer is events gets an events hop about its task: the vocabulary's multi-frame
/// rows in both spellings, a subscribe answering busbar's own refusal first, and an unlisted method
/// named as a stream.
#[test]
fn a_request_whose_answer_is_events_gets_an_events_hop() {
    for method in ["message/stream", "tasks/resubscribe"] {
        let hop = hop_of(&request(method), false, &mut Some(envelope(method))).expect(method);
        assert!(hop.opening, "{method}: about a task");
        assert_eq!(hop.subscribe, method == "tasks/resubscribe", "{method}");
    }
    let unlisted = AgentDisposition::Unlisted {
        method: "vendor/stream".into(),
        id: json!(7),
        version: "1.0",
    };
    let hop = hop_of(&unlisted, false, &mut Some(envelope("vendor/stream"))).expect("relayed");
    assert!(!hop.subscribe);
    assert!(
        hop.opening && hop.streams(),
        "the stream-named vendor method opens an event hop"
    );

    let unlisted = AgentDisposition::Unlisted {
        method: "vendor/frob".into(),
        id: json!(7),
        version: "1.0",
    };
    let mut vendor_request = Some(envelope("vendor/frob"));
    let hop =
        hop_of(&unlisted, false, &mut vendor_request).expect("a vendor unary method is relayed");
    assert!(hop.opening && !hop.subscribe && !hop.streams());
    assert_eq!(hop.request.as_deref(), Some(&envelope("vendor/frob")));
    assert!(
        vendor_request.is_none(),
        "the unary hop owns the supplied request"
    );

    let unary = hop_of(
        &request("message/send"),
        false,
        &mut Some(envelope("message/send")),
    );
    assert!(unary.is_some_and(|h| !h.subscribe && h.opening));
    assert!(hop_of(
        &request("tasks/list"),
        false,
        &mut Some(envelope("tasks/list"))
    )
    .is_none());
    assert!(
        hop_of(&request("message/stream"), false, &mut None).is_none(),
        "no request, no hop"
    );
}

/// THE ARRIVAL'S REQUEST IS READ ONCE AND NEVER COPIED: a hop takes the envelope the arrival was
/// decided over, and an arrival that makes no hop leaves it for the admission to read.
#[test]
fn a_hop_takes_the_request_and_no_hop_leaves_it() {
    let mut sent = Some(envelope("message/send"));
    let hop = hop_of(&request("message/send"), false, &mut sent).expect("a task hop");
    assert_eq!(hop.request.as_deref(), Some(&envelope("message/send")));
    assert!(sent.is_none(), "the hop took the request");
    let mut listed = Some(envelope("tasks/list"));
    assert!(hop_of(&request("tasks/list"), false, &mut listed).is_none());
    assert_eq!(
        listed,
        Some(envelope("tasks/list")),
        "no hop: the request is left for the admission"
    );
}

/// A BLANK `a2a-version` ON THE gRPC LINE NAMES NO VERSION: the line's own (`1.0`) stands, as for
/// an absent or empty one.
#[test]
fn a_blank_a2a_version_on_the_grpc_line_reads_as_the_lines_own_version() {
    use crate::agent_arrival::{decide_and_read, H_VERSION};
    for blank in ["", " ", " \t  "] {
        let head = |name: &str| (name == H_VERSION).then_some(blank);
        assert_eq!(
            framed_field(head, H_VERSION),
            Some(crate::framed::DEFAULT_VERSION),
            "{blank:?}"
        );
        let body = br#"{"jsonrpc":"2.0","id":7,"method":"SendMessage","params":{}}"#;
        let (decided, _) = decide_and_read(body, |name| framed_field(head, name));
        assert!(
            matches!(decided, AgentDisposition::Request { version: "1.0", .. }),
            "{blank:?}: {decided:?}"
        );
    }
    let named = |name: &str| (name == H_VERSION).then_some("0.3");
    assert_eq!(framed_field(named, H_VERSION), Some("0.3"));
}

/// Streamed hops declare streaming and the 600-second stream ceiling.
#[test]
fn a_streamed_hop_states_a_stream_and_the_tail_predevs_600_second_ceiling() {
    assert_eq!(crate::statement::TAIL.stream_ceiling_secs, 600);
    assert_eq!(crate::statement::STREAM_CEILING_SECS, 600);
    for method in [
        "message/stream",
        "tasks/resubscribe",
        "SendStreamingMessage",
        "SubscribeToTask",
    ] {
        let hop = hop_of(&request(method), false, &mut Some(envelope(method))).expect(method);
        assert!(hop.streams(), "{method}: its answer streams");
    }
    let unlisted = AgentDisposition::Unlisted {
        method: "vendor/stream".into(),
        id: json!(7),
        version: "1.0",
    };
    let hop = hop_of(&unlisted, false, &mut Some(envelope("vendor/stream"))).expect("relayed");
    assert!(hop.streams(), "an unlisted method named as a stream");
    for method in ["message/send", "tasks/get", "tasks/cancel"] {
        let hop = hop_of(&request(method), false, &mut Some(envelope(method))).expect("relayed");
        assert!(!hop.streams(), "{method}: one reply");
    }
}

/// The hook projection is the engine gate's: the method as the tool and `params` verbatim as the
/// arguments (`null` when absent); a body that is no JSON object projects nothing.
#[test]
fn the_hook_projection_is_the_method_and_its_params() {
    let send = br#"{"jsonrpc":"2.0","id":7,"method":"message/send","params":{"message":{"parts":[{"kind":"text","text":"hi"}]}}}"#;
    let got: Value = serde_json::from_slice(&hook_projection(send).unwrap()).unwrap();
    assert_eq!(
        got,
        json!({ "tool": "message/send",
            "arguments": { "message": { "parts": [{ "kind": "text", "text": "hi" }] } } })
    );
    let bare: Value = serde_json::from_slice(
        &hook_projection(br#"{"jsonrpc":"2.0","method":"tasks/list"}"#).unwrap(),
    )
    .unwrap();
    assert_eq!(bare, json!({ "tool": "tasks/list", "arguments": null }));
    assert_eq!(hook_projection(b"not json"), None);
    assert_eq!(hook_projection(b"[1]"), None);
}

/// THE INVOKE REWRITE CONTRACT, as the served engine applied a `prompt: rw` hook's reply to an A2A
/// submission's params: an object `content`, a JSON-string `content` that parses to an object, or a
/// role-less entry itself; the last usable entry wins; nothing usable refuses the submission; a reply that
/// cannot be read back is no rewrite at all (`Err`, the unit refused).
#[test]
fn a_rewrite_replaces_the_params_by_the_invoke_contract() {
    let params = |reply: Value| rewritten_params(&serde_json::to_vec(&reply).unwrap());
    let object = json!({ "message": { "parts": [{ "text": "[redacted]" }] } });
    assert_eq!(
        params(json!({ "messages": [{ "role": "user", "content": object }] })),
        Ok(Some(object.clone()))
    );
    assert_eq!(
        params(json!({ "messages": [{ "role": "user", "content": object.to_string() }] })),
        Ok(Some(object.clone()))
    );
    assert_eq!(
        params(json!({ "messages": [object.clone()] })),
        Ok(Some(object.clone()))
    );
    assert_eq!(
        params(json!({ "messages": [
            { "role": "user", "content": { "first": true } },
            { "role": "user", "content": "plain words" },
            { "role": "user", "content": object },
        ] })),
        Ok(Some(object.clone()))
    );
    assert!(params(json!({ "messages": [{ "role": "user" }] })).is_err());
    assert!(params(json!({ "messages": [{ "role": "user", "content": "7" }] })).is_err());
    assert!(params(json!({ "messages": [] })).is_err());
    assert!(params(json!({ "tools": [] })).is_err());
    assert!(rewritten_params(b"not json").is_err());

    let send = br#"{"jsonrpc":"2.0","id":7,"method":"message/send","params":{"message":{}}}"#;
    let (value, bytes) = with_params(send, object.clone()).unwrap();
    assert_eq!(
        value,
        json!({ "jsonrpc": "2.0", "id": 7, "method": "message/send", "params": object })
    );
    assert_eq!(serde_json::from_slice::<Value>(&bytes).unwrap(), value);
    assert_eq!(with_params(b"[1]", object.clone()), None);
}

/// On the HTTP+JSON line the body the kernel keeps is the params where the line's body is the
/// params (a message sent or streamed, a push config posted), and nothing where the path and the
/// query spell them.
#[test]
fn the_target_line_keeps_the_rewritten_params_as_its_body() {
    let route = |verb: &str, suffix: &str| {
        let target = format!("{}{suffix}", crate::MOUNT_PATH);
        statement::ROUTES
            .iter()
            .find(|r| r.verb == verb && r.target == target)
            .unwrap_or_else(|| panic!("{verb} {target}"))
    };
    let params = json!({ "message": { "parts": [] } });
    let bytes = serde_json::to_vec(&params).unwrap();
    for (verb, suffix) in [
        ("POST", crate::ROUTE_MESSAGE_SEND),
        ("POST", crate::ROUTE_MESSAGE_STREAM),
        ("POST", crate::ROUTE_PUSH_CONFIGS),
    ] {
        assert_eq!(
            target_body(route(verb, suffix), &params),
            Some(bytes.clone()),
            "{suffix}"
        );
    }
    assert_eq!(target_body(route("GET", crate::ROUTE_TASKS), &params), None);
    assert_eq!(target_body(route("POST", crate::ROUTE_TASK), &params), None);
}

fn ticket(slot: u32) -> Ticket {
    Ticket {
        slot,
        generation: 1,
    }
}

#[test]
fn one_look_flies_per_agent_and_its_waiters_land_with_it() {
    let flights = Flights::default();
    assert_eq!(
        flights.join("planner", ticket(1)),
        None,
        "the first unit looks"
    );
    assert_eq!(
        flights.join("planner", ticket(2)),
        Some(0),
        "the second waits"
    );
    assert_eq!(flights.join("planner", ticket(3)), Some(0), "and the third");
    assert_eq!(
        flights.join("scout", ticket(4)),
        None,
        "another agent flies apart"
    );
    assert_eq!(
        flights.state("planner", 0, ticket(2)),
        FlightState::InFlight,
        "still in flight"
    );
    assert_eq!(
        flights.land("planner"),
        vec![ticket(2), ticket(3)],
        "the waiters are woken"
    );
    assert_eq!(
        flights.state("planner", 0, ticket(2)),
        FlightState::Landed,
        "landed: the verdict is taken"
    );
    assert_eq!(
        flights.join("planner", ticket(5)),
        None,
        "the next due unit looks again"
    );
}

#[test]
fn an_abandoned_look_releases_its_flight_and_wakes_every_waiter_at_once() {
    let flights = Flights::default();
    assert_eq!(flights.join("planner", ticket(1)), None);
    assert_eq!(flights.join("planner", ticket(2)), Some(0));
    assert_eq!(flights.join("planner", ticket(3)), Some(0));
    assert_eq!(flights.join("scout", ticket(1)), None);
    let mut woken = flights.abandon(ticket(1));
    woken.sort_by_key(|t| t.slot);
    assert_eq!(
        woken,
        vec![ticket(2), ticket(3)],
        "every waiter, of every flight it held"
    );
    assert_eq!(
        flights.state("planner", 0, ticket(2)),
        FlightState::Released,
        "no verdict landed: the waiter looks again"
    );
    assert_eq!(
        flights.join("planner", ticket(2)),
        None,
        "and takes the flight over"
    );
    assert_eq!(
        flights.join("scout", ticket(4)),
        None,
        "the other flight was released too"
    );
}

/// Ported from busbar-a2a ingress_tests.rs::a_panicking_reverify_reraises_and_latches_unreachable_never_swallowed.
#[test]
fn a_panicking_look_surfaces_and_releases_its_flight_never_swallowed() {
    let flights = Flights::default();
    let (faulted, waiter) = (ticket(1), ticket(2));
    assert_eq!(flights.join("planner", faulted), None, "the due unit looks");
    let seen = flights
        .join("planner", waiter)
        .expect("a second due unit waits on its look");
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        looking((&flights, None, faulted), || -> bool {
            panic!("card fetch blew up")
        })
    }));
    assert!(
        outcome.is_err(),
        "a panicking look must surface as a panic, never a swallowed verdict"
    );
    assert_eq!(
        flights.state("planner", seen, waiter),
        FlightState::Released,
        "nothing landed: the waiter looks for itself"
    );
    assert_eq!(
        flights.join("planner", ticket(3)),
        None,
        "the next due unit takes the flight and looks again"
    );
}

/// A LOOK THAT RETURNS KEEPS ITS FLIGHT for the caller to land: the unwinding guard is disarmed, so
/// its drop releases nothing, the waiter still waits on the look in flight, and another due unit
/// joins it rather than looking afresh (the twin of the panicking look above, whose guard drops
/// armed and releases the flight).
#[test]
fn a_returning_look_keeps_its_flight_for_the_caller_to_land() {
    let flights = Flights::default();
    let (owner, waiter) = (ticket(1), ticket(2));
    assert_eq!(flights.join("planner", owner), None, "the due unit looks");
    let seen = flights
        .join("planner", waiter)
        .expect("a second due unit waits on its look");
    assert!(looking((&flights, None, owner), || true));
    assert_eq!(
        flights.state("planner", seen, waiter),
        FlightState::InFlight,
        "a returning look released nothing: the waiter still waits"
    );
    assert_eq!(
        flights.join("planner", ticket(3)),
        Some(seen),
        "the next due unit waits on the same flight"
    );
}

/// THE gRPC LINE'S OUTBOX: a whole answer is the rpc's one message at `OK` (no media type, no
/// length), or the status its error binds with the details field; an answer in events is one
/// message per event, each emitted on an answer of its own.
#[test]
fn the_framed_line_answers_messages_and_statuses() {
    use crate::framed::{Rpc, DETAILS_FIELD};
    use prost::Message as _;
    let task =
        json!({ "id": "t-1", "contextId": "c-1", "status": { "state": "TASK_STATE_COMPLETED" } });
    let ok = json!({ "jsonrpc": "2.0", "id": 1, "result": task });
    let ob = Outbox::framed(reply(200, &ok), Rpc::GetTask).expect("an outbox");
    assert!(matches!(ob.head, Some(AnswerHead::Framed)) && ob.final_status.is_none());
    assert!(ob.done && ob.queue.is_empty());
    let decoded = crate::proto::pb::Task::decode(ob.bytes.as_slice()).expect("a Task");
    assert_eq!(decoded.id, "t-1");

    let refused = json!({
        "jsonrpc": "2.0", "id": 1,
        "error": { "code": -32001, "message": "no task", "data": [{
            "@type": crate::ERROR_INFO_TYPE, "domain": crate::ERROR_INFO_DOMAIN,
            "reason": "TASK_NOT_FOUND" }] },
    });
    let ob = Outbox::framed(reply(404, &refused), Rpc::GetTask).expect("an outbox");
    assert!(matches!(ob.head, Some(AnswerHead::Framed)), "{:?}", ob.head);
    assert!(
        ob.bytes.is_empty() && !ob.messages,
        "a status's text is no message"
    );
    let end = ob
        .final_status
        .as_ref()
        .expect("the call ends with its status");
    assert_eq!(end.code, crate::framed::Code::NotFound as u32);
    assert_eq!(end.body, b"no task");
    let details = end.details.as_deref().expect("a status with details");
    assert!(!details.is_empty() && !details.ends_with('='));
    assert_eq!(DETAILS_FIELD, "grpc-status-details-bin");

    let event = |state: &str| {
        format!(
            "data: {}\n\n",
            json!({ "jsonrpc": "2.0", "id": 1, "result": { "statusUpdate": {
                "taskId": "t", "contextId": "c", "status": { "state": state } } } })
        )
    };
    let body = format!(
        "{}: ping\n\n{}",
        event("TASK_STATE_WORKING"),
        event("TASK_STATE_COMPLETED")
    );
    let part = PieceAnswer::Part(relay::Part {
        head: true,
        body: body.into_bytes(),
        last: true,
    });
    let ob = Outbox::framed(part, Rpc::SubscribeToTask).expect("an outbox");
    assert!(matches!(ob.head, Some(AnswerHead::Framed)) && ob.final_status.is_none());
    assert_eq!(
        ob.queue.len(),
        1,
        "the second event waits for an answer of its own"
    );
    assert!(crate::proto::pb::StreamResponse::decode(ob.bytes.as_slice()).is_ok());
    assert!(ob.done);

    let failed = format!(
        "data: {}\n\n",
        json!({ "jsonrpc": "2.0", "id": 1, "error": { "code": -32001, "message": "gone" } })
    );
    let part = PieceAnswer::Part(relay::Part {
        head: true,
        body: failed.into_bytes(),
        last: false,
    });
    let ob = Outbox::framed(part, Rpc::SubscribeToTask).expect("an outbox");
    assert!(
        matches!(ob.head, Some(AnswerHead::Framed))
            && ob.done
            && ob.final_status.as_ref().map(|f| f.code) == Some(5),
        "an error before any message ends the call with its status: {:?}",
        ob.final_status
    );
}

/// A STATUS ON THE gRPC LINE CLOSES AS ITS BLOCK, in the bytes and order predev's gRPC line closed
/// a call with: `grpc-status`, the percent-encoded `grpc-message` where there is a message, the
/// details field where there are details.
#[test]
fn a_framed_status_closes_as_its_block() {
    use crate::framed::{status_block, FramedReply};
    let reply = FramedReply {
        code: 5,
        body: b"no task {x}%".to_vec(),
        details: Some("CAE".to_string()),
    };
    assert_eq!(
        status_block(&reply),
        b"grpc-status: 5\r\ngrpc-message: no%20task%20%7Bx%7D%25\r\ngrpc-status-details-bin: CAE\r\n"
            .to_vec()
    );
    let bare = FramedReply {
        code: 13,
        body: Vec::new(),
        details: None,
    };
    assert_eq!(status_block(&bare), b"grpc-status: 13\r\n".to_vec());

    let service = crate::framed::SERVICE_PATH;
    assert!(crate::framed::on_service(&format!("{service}/SendMessage")));
    assert!(crate::framed::on_service(&format!(
        "{service}/NoSuchMethod?x=1"
    )));
    assert!(!crate::framed::on_service(&format!(
        "{service}Extra/SendMessage"
    )));
    assert!(!crate::framed::on_service("/a2a/agents/planner"));
}

/// THE gRPC LINE'S BOUNDARIES (SEAM-4l): a whole OK answer is one message, a status's text is no
/// message, and a stream that fails after its first message ends with its own final status.
#[test]
fn the_framed_line_marks_its_messages_and_a_late_failure() {
    use crate::framed::Rpc;
    let ok = json!({ "jsonrpc": "2.0", "id": 1, "result": {
        "id": "t-1", "contextId": "c-1", "status": { "state": "TASK_STATE_WORKING" } } });
    let whole = Outbox::framed(reply(200, &ok), Rpc::GetTask).expect("an outbox");
    assert!(whole.messages && whole.final_status.is_none());
    let refused = json!({ "jsonrpc": "2.0", "id": 1,
        "error": { "code": -32001, "message": "no task" } });
    let status = Outbox::framed(reply(404, &refused), Rpc::GetTask).expect("an outbox");
    assert!(!status.messages, "a status's text is no message");

    let event = format!(
        "data: {}\n\n",
        json!({ "jsonrpc": "2.0", "id": 1, "result": { "statusUpdate": {
            "taskId": "t", "contextId": "c", "status": { "state": "TASK_STATE_WORKING" } } } })
    );
    let failed = format!(
        "data: {}\n\n",
        json!({ "jsonrpc": "2.0", "id": 1, "error": { "code": -32603, "message": "boom" } })
    );
    let part = PieceAnswer::Part(relay::Part {
        head: true,
        body: format!("{event}{failed}").into_bytes(),
        last: false,
    });
    let late = Outbox::framed(part, Rpc::SubscribeToTask).expect("an outbox");
    assert!(late.messages && late.done);
    let end = late
        .final_status
        .expect("the stream ends with its own status");
    assert_eq!(end.code, crate::framed::Code::Internal as u32);
    assert_eq!(end.body, b"boom");

    let part = PieceAnswer::Part(relay::Part {
        head: false,
        body: failed.into_bytes(),
        last: false,
    });
    let after = Outbox::framed(part, Rpc::SubscribeToTask).expect("an outbox");
    assert!(after.done && after.bytes.is_empty() && after.final_status.is_some());
}

/// A long-running task streams many events and re-records the same pair each time, and re-recording
/// a held key must not evict any other.
#[test]
fn re_recording_the_same_pair_does_not_churn_the_map() {
    let map = BackendIds::default();
    for k in ["a", "b", "c"] {
        map.record(3, k.to_string(), format!("far-{k}"));
    }
    for _ in 0..1000 {
        map.record(3, "b".to_string(), "far-b".to_string());
    }
    assert_eq!(
        map.len(),
        3,
        "the map is still at its cap and nothing left it"
    );
    for k in ["a", "b", "c"] {
        assert_eq!(map.get(k), Some(format!("far-{k}")), "{k}");
    }

    map.record(3, "d".to_string(), "far-d".to_string());
    assert_eq!(map.len(), 3);
    assert_eq!(map.get("d"), Some("far-d".to_string()));
}

/// THE FAR END'S TASK IDS ARE FORGOTTEN OLDEST FIRST, never by how the callers' references sort:
#[test]
fn the_far_end_task_ids_are_forgotten_oldest_first_never_by_the_callers_name() {
    let map = BackendIds::default();
    map.record(3, "zed/t1".to_string(), "far-1".to_string());
    map.record(3, "amy/t2".to_string(), "far-2".to_string());
    map.record(3, "bob/t3".to_string(), "far-3".to_string());
    map.record(3, "cat/t4".to_string(), "far-4".to_string());
    assert_eq!(map.len(), 3, "the bound holds");
    assert_eq!(
        map.get("zed/t1"),
        None,
        "the id recorded longest ago is the one forgotten"
    );
    assert_eq!(
        map.get("amy/t2"),
        Some("far-2".to_string()),
        "a newer id stays, however its caller's reference sorts"
    );
}

/// A COMMITTED REWRITE BUSBAR CANNOT READ BACK REFUSES THE SUBMISSION — it does not fall back to
/// the `params` the hook said it had replaced (predev
/// `hook_tap_tests::a_committed_rewrite_busbar_cannot_read_back_is_refused_rather_than_silently_undone`).
#[test]
fn a_committed_rewrite_busbar_cannot_read_back_is_refused_rather_than_silently_undone() {
    let ok = rewritten_params(
        br#"{"messages":[{"role":"user","content":{"message":{"parts":[{"kind":"text","text":"rewritten"}]}}}]}"#,
    )
    .expect("an ordinary rewrite is read back")
    .expect("and used");
    assert_eq!(
        ok["message"]["parts"][0]["text"], "rewritten",
        "the control: a readable rewrite still lands, so the rule refuses unusable output rather \
         than refusing rewrites"
    );

    for unusable in [
        &b"not json at all"[..],
        &b""[..],
        &b"{\"message\": "[..],
        &b"7"[..],
        &b"[1,2,3]"[..],
        &b"null"[..],
        &b"\"message/send\""[..],
        &b"{\"messages\": 7}"[..],
    ] {
        assert!(
            rewritten_params(unusable).is_err(),
            "a committed rewrite busbar cannot use must REFUSE the submission; falling back to the \
             caller's original `params` silently undoes a redaction the hook reported as applied: \
             {:?}",
            String::from_utf8_lossy(unusable)
        );
    }
}

/// THE REFUSAL AN A2A CLIENT ACTUALLY READS (predev
/// `hook_tap_tests::the_unreadable_rewrite_refusal_is_a_conformant_a2a_internal_error`): the row of
/// A2A section 5.4 its status comes from, `InternalError`, `-32603`, `500`, echoing the caller's
/// id, in predev's words; the HTTP+JSON line answers the same row as its AIP-193 document.
#[test]
fn the_unreadable_rewrite_refusal_is_a_conformant_a2a_internal_error() {
    let id = json!("req-7");
    let refusal = unreadable_rewrite(Some(id.clone()));
    let rendered =
        crate::agent_arrival::render(crate::agent_arrival::Dialect::JsonRpc, &refusal, true);
    assert_eq!(
        rendered.status, 500,
        "the status the refusal answers is its row's own"
    );
    let body: Value = serde_json::from_slice(&rendered.body).expect("a JSON-RPC envelope");
    assert_eq!(
        body,
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": -32603,
                "message": "a rewrite hook attached to this agent committed a rewrite that busbar \
                            could not read back. The submission is refused rather than relayed \
                            with the params the hook said it had replaced.",
            },
        }),
        "predev's `rpcerror::body(&rpc_id, A2aError::Internal, ..)`, member for member"
    );
    let rest =
        crate::agent_arrival::render(crate::agent_arrival::Dialect::RestJson, &refusal, true);
    assert_eq!(rest.status, 500);
    let doc: Value = serde_json::from_slice(&rest.body).expect("an AIP-193 document");
    assert_eq!(doc["error"]["code"], 500, "{doc}");
    assert_eq!(doc["error"]["status"], "INTERNAL", "{doc}");
}

/// A NOTIFICATION is the plane's own to acknowledge wherever it arrives, never relayed: `202` and
/// no body at all, as the engine answered it (`jsonrpc::accepted`).
#[test]
fn a_notification_is_acknowledged_here_with_a_202_and_no_body() {
    let notice = AgentDisposition::Notice {
        method: "message/send".to_string(),
    };
    assert!(answered_here(&notice, true), "addressed to an agent");
    assert!(answered_here(&notice, false), "on the plane's own endpoint");
    assert!(hop_of(&notice, true, &mut Some(envelope("message/send"))).is_none());
    assert!(answered_here(&request("GetExtendedAgentCard"), false));
    assert!(!answered_here(&request("GetExtendedAgentCard"), true));
    assert!(!answered_here(&request("SendMessage"), false));
    assert_eq!(
        crate::task_door::notice_answer(),
        (crate::agent_arrival::STATUS_ACCEPTED, &b""[..])
    );
    assert_eq!(crate::agent_arrival::STATUS_ACCEPTED, 202);
}
/// `jsonrpc_client_issues_get_extended_agent_card`: a caller that addresses ONE agent and asks for
/// the extended card is asking for THAT agent's, and the door relays it as a TASK-LESS hop (a card
/// read opens no task), the caller's envelope posted verbatim at the agent's own path; on the
/// plane's own endpoint the same verb names no agent and makes no hop.
#[test]
fn an_addressed_extended_card_read_is_relayed_as_a_task_less_hop() {
    let row = crate::ops::row_for("GetExtendedAgentCard").expect("a row");
    let envelope = json!({ "jsonrpc": "2.0", "id": 7, "method": "GetExtendedAgentCard" });
    let asked = AgentDisposition::Request {
        row,
        id: json!(7),
        version: "1.0",
    };
    assert!(
        hop_of(&asked, false, &mut Some(envelope.clone())).is_none(),
        "the plane's own endpoint answers it locally"
    );
    let mut hop = hop_of(&asked, true, &mut Some(envelope.clone())).expect("a hop to the agent");
    assert!(!hop.opening, "a card read opens no task");
    hop.relay.bind(crate::binding::Binding::JsonRpc, &envelope);
    let PieceAnswer::Attempt(attempt) = hop.relay.on_piece(relay::Piece {
        from: relay::From::Kernel(Some("https://backend.agent.test/a2a")),
        bytes: &[],
        status: None,
        last: false,
    }) else {
        panic!("an attempt");
    };
    assert_eq!((attempt.verb, attempt.target.as_str()), ("POST", "/a2a"));
    let bytes = serde_json::to_vec(&envelope).unwrap();
    assert_eq!(
        hop.relay.on_piece(relay::Piece {
            from: relay::From::Caller,
            bytes: &bytes,
            status: None,
            last: true,
        }),
        PieceAnswer::ToFarEndLent,
        "the caller's envelope, verbatim: the piece itself, lent"
    );
}

/// THE VERSION THE STATEMENT NAMES IS THE CRATE'S: [`VERSION`] is written out (the purity rules
/// keep `env!` out of the plane's source), so this pins it to the manifest's `version`, exactly.
#[test]
fn the_statement_names_the_crates_version() {
    assert_eq!(VERSION, env!("CARGO_PKG_VERSION"));
}

/// G1-22: THE PARTS A KEY'S EARLIER VALUES RETIRED DO NOT ACCUMULATE: an agent whose over-ceiling
/// card changes on every connect tombstones the parts of the value it replaces, not every part any
/// value of the key ever had (a part an unwritten answer left behind is a stray the warm lists).
#[test]
fn the_tombstones_of_a_changing_split_record_stay_bounded() {
    let plane = A2aDoor::default();
    let size = 3 * busbar_contract::bounded::MAX_RECORD_BYTES;
    let mut previous_parts = 0;
    let mut last_tombstones = 0;
    for i in 0..50_u32 {
        let value: Vec<u8> = format!("{i:08}").bytes().cycle().take(size).collect();
        let writes = kept_records(&plane, crate::records::KIND_CARD, "planner", &value);
        let parts = writes
            .iter()
            .filter(|w| crate::split_record::is_part(&w.key) && !w.value.is_empty())
            .count();
        last_tombstones = writes.iter().filter(|w| w.value.is_empty()).count();
        if i < 49 {
            previous_parts = parts;
        }
    }
    assert!(previous_parts > 1, "the value is split");
    assert!(
        last_tombstones <= previous_parts,
        "{last_tombstones} tombstones for a key whose previous value had {previous_parts} parts"
    );
}

/// G1-25: AN APPROVAL MADE BETWEEN A REFRESH AND ITS PUBLICATION IS KEPT: the trust reset the
/// publication makes keeps every kept registration's approval as it stands then, not as it stood
/// when the refresh was judged.
#[test]
fn an_approval_made_while_a_refresh_publishes_is_kept() {
    let section =
        br#"{"planner": {"url": "https://planner.example/a2a", "pin": {"mechanism": "unpinned"}}}"#;
    let plane = A2aDoor::default();
    let cfg = agents_section(section).expect("the section reads");
    let spec = statement::agents_snapshot_spec(None, &["planner"]);
    let _ = plane.generations.publish_with(1, &spec, cfg);
    PlaneLife::published(&plane, 1);
    PlaneLife::refresh(&plane, section, 2).expect("the apply is judged");
    let approved: std::collections::BTreeMap<String, String> =
        [("plan".to_string(), "sha256:x".to_string())].into();
    plane.trust.insert(
        "planner".to_string(),
        crate::card_trust::TrustStanding {
            approved: Some(approved.clone()),
            ..Default::default()
        },
    );
    plane
        .cards
        .hold("planner", 1, json!({"name":"newly approved"}));
    PlaneLife::published(&plane, 2);
    assert_eq!(
        plane.cards.at("planner", 2).unwrap()["name"],
        "newly approved"
    );
    assert_eq!(
        plane
            .trust
            .get(&"planner".to_string())
            .and_then(|s| s.approved),
        Some(approved)
    );
}

/// The diagnostic lines `f` emits.
fn diags_of<R>(f: impl FnOnce() -> R) -> (R, Vec<String>) {
    let (sent, heard) = std::sync::mpsc::channel();
    let r = tracing::subscriber::with_default(crate::tests::capture::Capture(sent), f);
    (r, heard.try_iter().map(|(_, line)| line).collect())
}

/// A committed rewrite yielding no object refuses the submission and reports why.
#[test]
fn a_rewrite_that_yields_no_object_refuses_the_submission_and_says_so() {
    let reply = br#"{"messages": [{"role": "user", "content": "[REDACTED]"}]}"#;
    let (read, lines) = diags_of(|| rewritten_params(reply));
    assert!(read.is_err(), "the original params must not be relayed");
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(
        lines[0].contains("7045")
            && lines[0].contains("request")
            && lines[0].contains("submission is refused"),
        "{lines:?}"
    );
}

/// G1-54: A COMMITTED REWRITE BUSBAR CANNOT READ BACK IS REFUSED WITH ITS REASON NAMED: the caller
/// reads the fixed internal error, and the operator reads what the hook returned.
#[test]
fn an_unreadable_rewrite_names_its_reason() {
    let (read, lines) = diags_of(|| rewritten_params(b"not json"));
    assert!(read.is_err());
    assert!(
        lines
            .iter()
            .any(|l| l.contains("7046") && l.contains("not JSON")),
        "{lines:?}"
    );
    let (read, lines) = diags_of(|| rewritten_params(br#"{"tools": []}"#));
    assert!(read.is_err());
    assert!(
        lines
            .iter()
            .any(|l| l.contains("7046") && l.contains("messages")),
        "{lines:?}"
    );
}

/// G1-2: THE FAR END'S TASK ID IS UNTRUSTED INPUT, BOUNDED IN BYTES as the map is in entries: an id
/// longer than 1024 bytes is not held (the task keeps busbar's own id), so a far end answering
/// half-megabyte ids cannot make the bounded map hold gigabytes.
#[test]
fn a_far_end_task_id_past_the_byte_bound_is_not_held() {
    let map = BackendIds::default();
    map.record(3, "amy/t1".to_string(), "x".repeat(400_000));
    assert_eq!(map.get("amy/t1"), None);
    map.record(3, "amy/t2".to_string(), "y".repeat(1024));
    assert_eq!(map.get("amy/t2").map(|id| id.len()), Some(1024));
}

fn hook_projection(bytes: &[u8]) -> Option<Vec<u8>> {
    hook_view(bytes).map(|view| view.0)
}

#[test]
fn repeated_warm_failures_log_once_without_host_error_text() {
    let plane = A2aDoor::default();
    let (_, logs) = diags_of(|| {
        warm_unlisted(&plane, crate::records::KIND_CARD, "secret-host-detail");
        warm_unlisted(&plane, crate::records::KIND_CARD, "secret-host-detail");
    });
    assert_eq!(logs.len(), 1);
    assert!(logs[0].contains("stored card records"));
    assert!(!logs[0].contains("secret-host-detail"));
}

/// The schema is the actual lifecycle contract, not the protocol's request schema.
#[test]
fn settings_schema_matches_lifecycle_grammar() {
    assert_eq!(STATEMENT.settings_schema.ptr, SETTINGS_SCHEMA.as_ptr());
    assert_eq!(STATEMENT.settings_schema.len, SETTINGS_SCHEMA.len());
    let schema: serde_json::Value = serde_json::from_slice(SETTINGS_SCHEMA).unwrap();
    assert_eq!(
        schema["$defs"]["secret"],
        busbar_contract::secret_ref::oneof_schema()
    );
    let validator = settings_profile::validator(&schema).unwrap();
    for (source, accepted) in [
        (r#"{}"#, true),
        (r#"{"agents":{}}"#, true),
        (
            r#"{"a":{"url":"https://agent.example/a2a","pin":{"mechanism":"unpinned"}}}"#,
            true,
        ),
        (
            r#"{"a":{"url":"https://agent.example/a2a","pin":{"mechanism":"mtls"},"client_identity":{"cert":{"module":"fixture-env-source","settings":{"name":"CERT"}},"key":{"module":"fixture-file-source","settings":{"path":"/run/key"}}},"upstream_credential":{"secret":{"module":"fixture-env-source","settings":{"name":"TOKEN"}},"lease_ttl_ms":5000}}}"#,
            true,
        ),
        (
            r#"{"a":{"url":"https://agent.example/a2a","pin":{"mechanism":"unpinned"},"upstream_credential":{"secret":"none","lease_ttl_ms":5000}}}"#,
            true,
        ),
        (
            r#"{"a":{"url":"https://agent.example/a2a","pin":{"mechanism":"unpinned"},"upstream_credential":{"secret":{"template":{"text":"token-${TOKEN}","source":{"module":"fixture-env-source","setting":"name"}}},"lease_ttl_ms":5000}}}"#,
            true,
        ),
        // A lifecycle call receives canonical references; source shorthand needs admission first.
        (
            r#"{"a":{"url":"https://agent.example/a2a","pin":{"mechanism":"unpinned"},"upstream_credential":{"secret":{"env":"TOKEN"},"lease_ttl_ms":5000}}}"#,
            false,
        ),
        (
            r#"{"a":{"url":"https://agent.example/a2a","pin":{"mechanism":"unpinned"},"upstream_credential":{"secret":{"file":"/run/key"},"lease_ttl_ms":5000}}}"#,
            false,
        ),
        (
            r#"{"hooks":["audit"],"upstream_credentials":"own","pools":{"p":{"members":["a",{"name":"b"}]}}}"#,
            true,
        ),
        (r#"{"pools":{"p":{"members":[null,1,{}]}}}"#, true),
        (r#"{"a":{"url":"https://agent.example/a2a"}}"#, false),
        (
            r#"{"a":{"url":"https://agent.example/a2a","pin":{"mechanism":"mtls"}}}"#,
            false,
        ),
        (r#"{"upstream_credentials":"passthrough"}"#, false),
        (r#"{"upstream_credentials":null}"#, false),
        (
            r#"{"a":{"url":"https://agent.example/a2a","pin":{"mechanism":"unpinned"},"egress_scopes":["b"]}}"#,
            false,
        ),
        (
            r#"{"a":{"url":"https://agent.example/a2a","pin":{"mechanism":"unpinned"},"upstream_credential":{"secret":"literal-key","lease_ttl_ms":5000}}}"#,
            false,
        ),
        (
            r#"{"a":{"url":"https://agent.example/a2a","pin":{"mechanism":"unpinned"},"upstream_credential":{"secret":{"module":"fixture-env-source","settings":{"name":"TOKEN"}},"lease_ttl_ms":0}}}"#,
            false,
        ),
        (
            r#"{"a":{"url":"https://agent.example/a2a","pin":{"mechanism":"unpinned"},"typo":true}}"#,
            false,
        ),
    ] {
        let value: serde_json::Value = serde_json::from_str(source).unwrap();
        let bytes = serde_json::to_vec(&value).unwrap();
        assert_eq!(
            agents_section(&statement::dealt_section(&bytes)).is_ok(),
            accepted,
            "lifecycle: {source}"
        );
        assert_eq!(validator.is_valid(&value), accepted, "schema: {source}");
    }
}

#[test]
fn settings_schema_describes_owned_push_trust_separately() {
    let schema: serde_json::Value = serde_json::from_slice(SETTINGS_SCHEMA).unwrap();
    let validator = jsonschema::validator_for(&schema["$defs"]["owned_sections"]).unwrap();
    for (source, accepted) in [
        (r#"{}"#, true),
        (r#"{"agent_push":null}"#, true),
        (r#"{"agent_push":{}}"#, true),
        (r#"{"agent_push":{"ca":"PUBLIC CERTIFICATE"}}"#, true),
        (r#"{"agent_push":{"ca":" "}}"#, false),
        (r#"{"agent_push":{"cert":"PUBLIC CERTIFICATE"}}"#, false),
        (r#"{"agent_push":"PUBLIC CERTIFICATE"}"#, false),
    ] {
        let value: serde_json::Value = serde_json::from_str(source).unwrap();
        let bytes = serde_json::to_vec(&value).unwrap();
        assert_eq!(
            statement::read_push_section(&bytes).is_ok(),
            accepted,
            "lifecycle: {source}"
        );
        assert_eq!(validator.is_valid(&value), accepted, "schema: {source}");
    }
}

#[test]
fn settings_schema_integer_tokens_match_native_parser() {
    let schema: serde_json::Value = serde_json::from_slice(SETTINGS_SCHEMA).unwrap();
    let profile = settings_profile::validator(&schema).unwrap();
    let standard = jsonschema::validator_for(&schema).unwrap();
    assert_eq!(schema["x-busbar-settings-profile"], "integer-token-v1");
    for (pointer, template, integer, kind) in [(
        r#"/$defs/agent/properties/upstream_credential/anyOf/0/properties/lease_ttl_ms"#,
        r#"{"a":{"url":"https://agent.example/a2a","pin":{"mechanism":"unpinned"},"upstream_credential":{"secret":{"module":"fixture-env-source","settings":{"name":"API_KEY"}},"lease_ttl_ms":TOKEN}}}"#,
        "1",
        "unsigned",
    )] {
        assert_eq!(
            schema.pointer(pointer).unwrap()["x-busbar-integer-token"],
            kind
        );
        for (token, accepted) in [
            (integer.to_string(), true),
            (format!("{integer}.0"), false),
            (format!("{integer}e0"), false),
            (format!("{integer}E+0"), false),
        ] {
            let text = template.replace("TOKEN", &token);
            let value: serde_json::Value = serde_json::from_str(&text).unwrap();
            assert!(
                standard.is_valid(&value),
                "standard mathematical integer: {text}"
            );
            assert_eq!(profile.is_valid(&value), accepted, "profile: {text}");
            assert_eq!(
                agents_section(&statement::dealt_section(text.as_bytes())).is_ok(),
                accepted,
                "native: {text}"
            );
        }
        // Do not infer signed negative-zero behavior from a regular expression:
        // the profile must agree with the actual lifecycle parser.
        for token in [
            "null",
            "0",
            "-0",
            "-0.0",
            "0e0",
            "-1",
            "18446744073709551616",
        ] {
            let text = template.replace("TOKEN", token);
            let value: serde_json::Value = serde_json::from_str(&text).unwrap();
            assert_eq!(
                profile.is_valid(&value),
                agents_section(&statement::dealt_section(text.as_bytes())).is_ok(),
                "native sign/range: {text}"
            );
        }
    }
}

#[test]
fn authored_configuration_profile_uses_actual_raw_agents_and_push_parsers() {
    let document: serde_json::Value = serde_json::from_slice(SETTINGS_SCHEMA).unwrap();
    let profile = &document["x-busbar-user-configuration"];
    assert_eq!(profile["version"], 1);
    assert_eq!(profile["context"], "raw_user_configuration");
    assert_eq!(profile["schema_ref"], "#/$defs/user_configuration");
    let schema = serde_json::json!({"$schema":"https://json-schema.org/draft/2020-12/schema","x-busbar-settings-profile":"integer-token-v1","$defs":document["$defs"],"$ref":profile["schema_ref"]});
    let validator = settings_profile::validator(&schema).unwrap();
    for (source, accepted) in [
        (r#"{}"#, true),
        (r#"{"agents":null,"agent_push":null}"#, true),
        (
            r#"{"agents":{"a":{"url":"https://agent.example/a2a","pin":{"mechanism":"unpinned"},"protocol_version":"1.0"}}}"#,
            false,
        ),
        (
            r#"{"agents":{"a":{"url":"https://agent.example/a2a","pin":{"mechanism":"unpinned"},"hooks":["audit"]}},"agent_push":{"ca":"PUBLIC CERTIFICATE"}}"#,
            true,
        ),
        (
            r#"{"agents":{"a":{"url":"https://agent.example/a2a","pin":{"mechanism":"unpinned"},"upstream_credential":{"secret":{"module":"fixture-env-source","settings":{"name":"TOKEN"}},"lease_ttl_ms":1}}}}"#,
            true,
        ),
        (
            r#"{"agents":{"a":{"url":"https://agent.example/a2a"}}}"#,
            false,
        ),
        (
            r#"{"agents":{"a":{"url":"https://agent.example/a2a","pin":{"mechanism":"unpinned"},"egress_scopes":["b"]}}}"#,
            false,
        ),
        (r#"{"agents":{"pools":{"p":{"members":["a"]}}}}"#, false),
        (r#"{"agent_push":{"ca":" "}}"#, false),
    ] {
        let value: serde_json::Value = serde_json::from_str(source).unwrap();
        let agents = value
            .get("agents")
            .filter(|value| !value.is_null())
            .cloned()
            .unwrap_or_else(|| serde_json::json!({}));
        let actual = serde_json::from_value::<crate::a2a::config::AgentsCfg>(agents).is_ok()
            && statement::read_push_section(source.as_bytes()).is_ok();
        assert_eq!(actual, accepted, "parser: {source}");
        assert_eq!(validator.is_valid(&value), accepted, "schema: {source}");
    }
    // `pools` is host-reserved even when its value looks like a valid registration.
    // Standalone plane parsers do not replace the host's reserved-name boundary.
    let reserved: serde_json::Value = serde_json::from_str(r#"{"agents":{"pools":{"url":"https://example.test/endpoint","pin":{"mechanism":"unpinned"}}}}"#).unwrap();
    assert!(
        !validator.is_valid(&reserved),
        "raw authoring must not offer the runtime pool projection as a registration"
    );
    assert!(
        document["$defs"]["section"]["properties"]
            .get("pools")
            .is_some(),
        "existing lifecycle pool projection stays intact"
    );
}

#[path = "task_backend_publication.rs"]
mod task_backend_publication;
