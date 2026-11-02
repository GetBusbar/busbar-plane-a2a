// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Exercises session projection through the door path.

#[path = "support/door_facts.rs"]
#[allow(dead_code)]
mod door_facts;

use busbar_contract::abi::mechanism::call::{InHead, OutHead, Outcome};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::plane::{slot, Ops, ProjectIn, ProjectOut};
use serde_json::json;

/// The door's plane ops, as the dispatcher reads them off the door.
fn ops() -> &'static Ops {
    // SAFETY: the door is a `'static` table whose ops are the plane kind's.
    unsafe { &*(*busbar_plane_a2a::door()).ops().cast::<Ops>() }
}

/// One `project` of `body` arriving on claim `claim` at `target`, through the door's own entry,
fn project_session(claim: usize, target: &str, body: &[u8]) -> (Outcome, Option<String>) {
    let (outcome, session, _) = project_view(claim, target, body);
    (outcome, session)
}

fn project_view(
    claim: usize,
    target: &str,
    body: &[u8],
) -> (Outcome, Option<String>, Option<serde_json::Value>) {
    use busbar_contract::abi::hook::SignalEntry;
    use busbar_contract::abi::mechanism::call::{AbiStr, Blob, BLOB_OCTETS};
    use busbar_contract::abi::sdk::door::{blank_in, blank_out};
    let mut signals = [SignalEntry {
        id: 0,
        tag: 0,
        value: busbar_contract::abi::hook::SignalValue { u64_: 0 },
    }; 4];
    let mut arena = vec![0u8; 4096];
    let mut messages = [busbar_contract::abi::hook::MessageView {
        role: AbiStr::of_bytes(b""),
        text: AbiStr::of_bytes(b""),
    }; 4];
    let input = ProjectIn {
        claim: u32::try_from(claim).unwrap(),
        // SAFETY: `target` and `body` outlive `input`, which is read only inside this function.
        target: unsafe { AbiStr::from_raw_parts(target.as_ptr(), target.len()) },
        // SAFETY: as `target`.
        body: unsafe { Blob::from_raw_parts(body.as_ptr(), body.len(), BLOB_OCTETS, 0) },
        signals_buf: signals.as_mut_ptr(),
        signals_cap: signals.len(),
        arena_buf: arena.as_mut_ptr(),
        arena_cap: arena.len(),
        messages_buf: messages.as_mut_ptr(),
        messages_cap: messages.len(),
        head: InHead {
            size: std::mem::size_of::<ProjectIn>() as u32,
            op: slot::PROJECT,
            ticket: Ticket::NONE,
            ..blank_in()
        },
        ..blank_in()
    };
    let mut out: ProjectOut = blank_out();
    out.head = OutHead {
        size: std::mem::size_of::<ProjectOut>() as u32,
        ..blank_out()
    };

    let project = ops().project.expect("the door states project");
    let outcome = project(
        std::ptr::null_mut(),
        std::ptr::from_ref(&input).cast(),
        std::ptr::from_mut(&mut out).cast(),
    )
    .outcome();
    // SAFETY: the production project operation above wrote into these live host buffers. Its
    // current A2A projection emits no signals, so no recognized tag can select an uninitialized
    // union member; the initialized signal backing storage also remains live through this check.
    unsafe {
        busbar_contract::abi::plane::check::check_project(
            outcome,
            &out,
            &busbar_contract::abi::plane::check::ProjectHost {
                signals: &signals,
                signals_cap: signals.len() as u64,
                messages: &messages,
                messages_cap: messages.len() as u64,
                arena: (arena.as_ptr(), arena.len() as u64),
                rewrite: false,
            },
        )
    }
    .expect("the answer passes the loader's check");
    let s = out.view.session;
    let session = (!s.ptr().is_null()).then(|| {
        assert_eq!(s.fmt, BLOB_OCTETS);
        let at = s.ptr() as usize - arena.as_ptr() as usize;
        String::from_utf8(arena[at..at + s.len()].to_vec()).unwrap()
    });
    let body = out.body;
    let projection =
        (body.offset != busbar_contract::abi::mechanism::check::SPAN_ABSENT).then(|| {
            let at = body.offset as usize;
            serde_json::from_slice(&arena[at..at + body.len as usize]).unwrap()
        });
    (outcome, session, projection)
}

#[test]
fn the_projection_and_session_keep_the_same_request_values() {
    let params = json!({
        "message": {"role":"user", "messageId":"m-one", "contextId":"ctx-one",
                    "parts":[{"text":"screen this"}, {"data":{"id":"user-id","nested":[1,2,3]}}]},
        "metadata": {"name":"user-name", "timestamp":"user-time"}
    });
    let body = serde_json::to_vec(
        &json!({"jsonrpc":"2.0", "id":7, "method":"message/send", "params":params}),
    )
    .unwrap();
    let (outcome, session, projection) = project_view(
        claim_of("POST", "/a2a/agents/{agent_id}"),
        "/a2a/agents/vendor",
        &body,
    );
    assert_eq!(outcome, Outcome::Ready);
    assert_eq!(session.as_deref(), Some("ctx-one"));
    assert_eq!(
        projection,
        Some(json!({"tool":"message/send", "arguments":params}))
    );
}

/// The claim the door states for `verb target`.
fn claim_of(verb: &str, target: &str) -> usize {
    door_facts::claim(verb, target) as usize
}

/// The projected session is the message's context id.
#[test]
fn project_writes_the_messages_context_id_as_the_session() {
    let document = claim_of("POST", "/a2a/agents/{agent_id}");
    let send = |context: Option<&str>| {
        let mut message = json!({ "role": "user", "messageId": "m1", "parts": [{ "text": "hi" }] });
        if let Some(c) = context {
            message["contextId"] = json!(c);
        }
        serde_json::to_vec(&json!({
            "jsonrpc": "2.0", "id": 1, "method": "message/send",
            "params": { "message": message },
        }))
        .unwrap()
    };
    assert_eq!(
        project_session(document, "/a2a/agents/planner", &send(Some("ctx-7"))),
        (Outcome::Ready, Some("ctx-7".to_string()))
    );
    assert_eq!(
        project_session(document, "/a2a/agents/planner", &send(None)),
        (Outcome::Ready, None)
    );
    assert_eq!(
        project_session(document, "/a2a/agents/planner", &send(Some(""))),
        (Outcome::Ready, None),
        "an empty contextId is no session"
    );

    let target = claim_of("POST", "/a2a/message:send");
    let rest = serde_json::to_vec(&json!({
        "message": {
            "role": "ROLE_USER", "messageId": "m2", "contextId": "ctx-9",
            "parts": [{ "text": "hi" }],
        },
    }))
    .unwrap();
    assert_eq!(
        project_session(target, "/a2a/message:send", &rest),
        (Outcome::Ready, Some("ctx-9".to_string()))
    );
}
