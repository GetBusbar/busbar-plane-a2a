// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! One relayed event, read as the served engine reads it: busbar's identity on it, its id
//! correlated, its state and artifact read through either shape, anything else passed through.

use super::*;
use serde_json::json;

/// A far end's frame answering request 11 with `result`.
fn frame_of(result: Value) -> String {
    format!(
        "data: {}\n\n",
        json!({ "jsonrpc": "2.0", "id": 11, "result": result })
    )
}

fn data_of(sse: &[u8]) -> Value {
    let text = std::str::from_utf8(sse).unwrap();
    serde_json::from_str(text.strip_prefix("data: ").unwrap().trim_end()).unwrap()
}

/// An event leaves under busbar's identity, with the matched skill; the far end's own ids are read
/// first and never reach the caller.
#[test]
fn an_event_leaves_under_busbars_identity() {
    let ev = read_event(
        &frame_of(json!({
            "taskId": "BACKEND-OWN-TASK-ID",
            "contextId": "BACKEND-OWN-CONTEXT",
            "kind": "status-update",
            "status": { "state": "working" }
        })),
        &json!(11),
        "busbar-task-1",
        "ctx-mine",
        Some("plan"),
        &[],
    )
    .expect("correlated");
    let doc = data_of(&ev.sse);
    assert_eq!(doc["id"], 11);
    assert_eq!(doc["result"]["taskId"], "busbar-task-1");
    assert!(doc["result"].get("id").is_none(), "no stray id: {doc}");
    assert_eq!(doc["result"]["contextId"], "ctx-mine");
    assert_eq!(doc["result"]["metadata"]["busbar/skill"], "plan");
    let rendered = String::from_utf8(ev.sse).unwrap();
    assert!(!rendered.contains("BACKEND-OWN"), "{rendered}");
    assert_eq!(ev.state, Some(TaskState::Working));
    assert_eq!(ev.backend_task_id.as_deref(), Some("BACKEND-OWN-TASK-ID"));
    assert!(!ev.artifact);
}

/// The v1.0 wrappers are read through: a status update's state and an artifact update's chunk.
#[test]
fn a_wrapped_event_reports_its_state_and_its_artifact() {
    let status = read_event(
        &frame_of(json!({ "statusUpdate": {
            "taskId": "far-1", "contextId": "c", "status": { "state": "TASK_STATE_INPUT_REQUIRED" }
        } })),
        &json!(11),
        "t",
        "c",
        None,
        &[],
    )
    .unwrap();
    assert_eq!(status.state, Some(TaskState::InputRequired));
    assert_eq!(status.backend_task_id.as_deref(), Some("far-1"));
    assert_eq!(
        data_of(&status.sse)["result"]["statusUpdate"]["taskId"],
        "t"
    );

    let chunk = read_event(
        &frame_of(json!({ "artifactUpdate": { "taskId": "far-1", "artifact": { "parts": [] } } })),
        &json!(11),
        "t",
        "c",
        None,
        &[],
    )
    .unwrap();
    assert!(chunk.artifact);
    assert_eq!(chunk.state, None, "an artifact reports no state");
}

/// A keep-alive, a comment and a frame that is not JSON pass byte for byte, read as nothing.
#[test]
fn a_frame_that_is_not_a_response_passes_through_byte_for_byte() {
    for passed in [
        ": keep-alive\n\n",
        "data: not json\n\n",
        "data: {\"x\":1}\n\n",
    ] {
        let ev = read_event(passed, &json!(11), "t", "c", None, &[]).unwrap();
        assert_eq!(ev.sse, passed.as_bytes(), "{passed:?}");
        assert_eq!((ev.state, ev.artifact), (None, false));
    }
}

/// A frame answering another request refuses the hop; an `error` frame is relayed under the
/// caller's id as it stands.
#[test]
fn an_uncorrelated_frame_is_refused_and_an_error_frame_relayed() {
    let other = "data: {\"jsonrpc\":\"2.0\",\"id\":99,\"result\":{}}\n\n";
    assert!(read_event(other, &json!(11), "t", "c", None, &[]).is_err());

    let error =
        "data: {\"jsonrpc\":\"2.0\",\"id\":11,\"error\":{\"code\":-32603,\"message\":\"x\"}}\n\n";
    let ev = read_event(error, &json!(11), "t", "c", None, &[]).unwrap();
    let doc = data_of(&ev.sse);
    assert_eq!(doc["error"]["code"], -32603);
    assert_eq!(doc["id"], 11);
    assert_eq!(ev.state, None);
}

/// An HTTP+JSON far end's frame carries the bare event: it is wrapped as the result of the caller's
/// request so the one reader reads it; a frame with no JSON payload passes as it is.
#[test]
fn a_bare_event_is_wrapped_as_the_result_of_the_request() {
    let wrapped = rewrap("data: {\"kind\":\"status-update\"}\n\n", &json!("rest"));
    let doc = data_of(wrapped.as_bytes());
    assert_eq!(
        doc,
        json!({ "jsonrpc": "2.0", "id": "rest", "result": { "kind": "status-update" } })
    );
    assert_eq!(rewrap(": ping\n\n", &json!(1)), ": ping\n\n");
}

/// The HTTP+JSON line answers each event's bare result; an error frame and a keep-alive pass, and
/// each line keeps its own terminator.
#[test]
fn the_target_line_answers_each_events_bare_result() {
    let events = b"data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"a\":1}}\r\n\r\n: ping\n\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":1}}\n\n";
    assert_eq!(
        String::from_utf8(reframe_events(events)).unwrap(),
        "data: {\"a\":1}\r\n\r\n: ping\n\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":1}}\n\n"
    );
}

/// Ported from busbar-a2a a2a/tests/rest_tests.rs::non_response_frames_are_passed_through.
/// Keep-alives, comments and a backend's own frames are passed through: content busbar does not
/// read is content busbar does not rewrite.
#[test]
fn non_response_frames_are_passed_through() {
    for frame in [
        &b": keep-alive\n\n"[..],
        &b"event: ping\ndata: {\"hello\":1}\n\n"[..],
        &b"data: not json at all\n\n"[..],
    ] {
        assert_eq!(
            reframe_events(frame),
            frame.to_vec(),
            "{}",
            String::from_utf8_lossy(frame)
        );
    }
}

/// A `result` that is no object is no event about a task: the hop is refused as one whose answer
/// the plane cannot read, never relayed as an invented task. RED: it became `{"kind":"task"}`.
#[test]
fn an_event_whose_result_is_no_object_refuses_the_hop() {
    for result in [json!("done"), json!([1]), json!(3), json!(null)] {
        assert_eq!(
            read_event(&frame_of(result.clone()), &json!(11), "t", "c", None, &[]),
            Err(crate::relay::HopRefusal::NotJson),
            "{result}"
        );
    }
}

/// THE FAR END'S EVENT BYTES, KEPT: member order, an integer past 64 bits and a number past
/// `f64`'s range reach the caller as written, busbar's identity spliced in, and a payload the far
/// end broke over lines stays one event, each of its lines a `data:` line.
#[test]
fn an_event_keeps_the_far_ends_bytes_and_its_lines() {
    let frame = "data: {\"jsonrpc\":\"2.0\",\"id\":11,\"result\":{\"taskId\":\"far\",\ndata:  \"n\":123456789012345678901234567890,\"kind\":\"status-update\",\"big\":1e400}}\n\n";
    let ev = read_event(frame, &json!(11), "t", "c", None, &[]).unwrap();
    assert_eq!(
        String::from_utf8(ev.sse).unwrap(),
        "data: {\"jsonrpc\":\"2.0\",\"id\":11,\"result\":{\"taskId\":\"t\",\ndata:  \"n\":123456789012345678901234567890,\"kind\":\"status-update\",\"big\":1e400,\"contextId\":\"c\"}}\n\n"
    );
    assert_eq!(ev.backend_task_id.as_deref(), Some("far"));
}

/// AN HTTP+JSON FAR END'S BARE EVENT IS WRAPPED AROUND ITS OWN BYTES. RED: it was re-serialised
/// (members re-sorted, the long integer rounded) and a number past `f64`'s range passed the frame
/// on unread, the far end's ids with it.
#[test]
fn a_bare_event_is_wrapped_around_its_own_bytes() {
    let bare = "data: {\"z\":1,\"kind\":\"status-update\",\"n\":123456789012345678901234567890,\"big\":1e400}\n\n";
    assert_eq!(
        rewrap(bare, &json!(7)),
        "data: {\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{\"z\":1,\"kind\":\"status-update\",\"n\":123456789012345678901234567890,\"big\":1e400}}\n\n"
    );
    assert_eq!(rewrap("data: \n\n", &json!(7)), "data: \n\n");
}

/// THE HTTP+JSON LINE'S EVENT IS THE RESULT'S OWN BYTES, cut out of the JSON-RPC event, over as
/// many `data:` lines as the result has lines. RED: the result was re-serialised (members
/// re-sorted, the long integer rounded), and an event over several `data:` lines passed whole.
#[test]
fn the_target_lines_event_is_the_results_own_bytes() {
    let events = b"data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"z\":1,\"a\":123456789012345678901234567890,\"big\":1e400}}\n\nid: 4\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"z\":1,\ndata: \"a\":2}}\n\n";
    assert_eq!(
        String::from_utf8(reframe_events(events)).unwrap(),
        "data: {\"z\":1,\"a\":123456789012345678901234567890,\"big\":1e400}\n\nid: 4\ndata: {\"z\":1,\ndata: \"a\":2}\n\n"
    );
}

/// G2-21: a task SNAPSHOT is not an artifact chunk, whatever `artifacts` it carries (an empty
/// list, or a final snapshot repeating what was streamed): only an artifact update counts.
#[test]
fn a_task_snapshot_with_artifacts_relays_no_artifact_chunk() {
    for result in [
        json!({ "task": { "id": "far-1", "status": { "state": "TASK_STATE_WORKING" }, "artifacts": [] } }),
        json!({ "id": "far-1", "kind": "task", "status": { "state": "completed" },
            "artifacts": [{ "artifactId": "a", "parts": [] }] }),
    ] {
        let ev = read_event(&frame_of(result.clone()), &json!(11), "t", "c", None, &[]).unwrap();
        assert!(!ev.artifact, "{result}");
    }
    let bare = read_event(
        &frame_of(json!({ "kind": "artifact-update", "taskId": "far-1",
            "artifact": { "artifactId": "a", "parts": [] } })),
        &json!(11),
        "t",
        "c",
        None,
        &[],
    )
    .unwrap();
    assert!(bare.artifact);
}
