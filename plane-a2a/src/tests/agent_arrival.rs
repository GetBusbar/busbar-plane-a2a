// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! One JSON-RPC arrival decided in the served order, and its refusal rendered in the line's

use super::*;

/// One arrival's disposition alone.
fn decide_arrival<'a>(
    body: &[u8],
    field: impl Fn(&str) -> Option<&'a str> + Copy,
) -> AgentDisposition {
    decide_and_read(body, field).0
}

/// A head with the given `content-type` and `a2a-version`.
fn head<'a>(
    ct: Option<&'a str>,
    version: Option<&'a str>,
) -> impl Fn(&str) -> Option<&'a str> + Copy {
    with_origin(None, ct, version)
}

/// A head with the given `origin`, `content-type` and `a2a-version`.
fn with_origin<'a>(
    origin: Option<&'a str>,
    ct: Option<&'a str>,
    version: Option<&'a str>,
) -> impl Fn(&str) -> Option<&'a str> + Copy {
    move |name: &str| match name {
        H_ORIGIN => origin,
        H_CONTENT_TYPE => ct,
        H_VERSION => version,
        _ => None,
    }
}

fn refused(d: AgentDisposition) -> AgentRefusal {
    match d {
        AgentDisposition::Refused(r) => r,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

const SEND: &[u8] = br#"{"jsonrpc":"2.0","id":7,"method":"SendMessage","params":{}}"#;

#[test]
fn malformed_skill_and_output_mode_fields_are_invalid_params_before_routing() {
    for method in [
        "message/send",
        "SendMessage",
        "message/stream",
        "SendStreamingMessage",
    ] {
        for params in [
            json!({"metadata": {"skill": 7}}),
            json!({"metadata": {"skill": ["plan"]}}),
            json!({"configuration": {"acceptedOutputModes": "text/plain"}}),
            json!({"configuration": {"acceptedOutputModes": [1, null]}}),
            json!({"configuration": {"acceptedOutputModes": ["text/plain", false]}}),
            json!({"configuration": {"accepted_output_modes": ["text/plain", null]}}),
        ] {
            let envelope =
                json!({"jsonrpc":"2.0", "id":"request-7", "method":method, "params":params});
            let bytes = serde_json::to_vec(&envelope).unwrap();
            let (disposition, read) = decide_and_read(&bytes, head(None, None));
            let refusal = refused(disposition);
            assert_eq!(
                (refusal.status, refusal.code),
                (400, CODE_INVALID_PARAMS),
                "{envelope}"
            );
            assert_eq!(refusal.id, Some(json!("request-7")));
            assert_eq!(read, Some(envelope.clone()));
            assert!(
                refusal.message.starts_with("params."),
                "{}",
                refusal.message
            );
            assert!(!refusal.message.contains("request-7"));
        }
    }
}

#[test]
fn absent_null_and_well_typed_shape_fields_keep_the_existing_request_path() {
    for params in [
        json!({}),
        json!({"metadata": {"skill": null}, "configuration": {"acceptedOutputModes": null}}),
        json!({"metadata": {"skill": "plan"}, "configuration": {"acceptedOutputModes": []}}),
        json!({"metadata": {"skill": "plan"}, "configuration": {"acceptedOutputModes": ["text/plain"]}}),
        json!({"configuration": {"accepted_output_modes": ["application/json"]}}),
    ] {
        let envelope = json!({"jsonrpc":"2.0", "id":7, "method":"SendMessage", "params":params});
        let bytes = serde_json::to_vec(&envelope).unwrap();
        assert!(
            matches!(
                decide_arrival(&bytes, head(None, None)),
                AgentDisposition::Request { .. }
            ),
            "{envelope}"
        );
    }
}

#[test]
fn shape_validation_preserves_notifications_and_generic_namespace_requests() {
    let params = json!({"metadata":{"skill":7},"configuration":{"acceptedOutputModes":[false]}});
    let generic = json!({"jsonrpc":"2.0","id":"opaque","method":"vendor/Thing","params":params});
    let (disposition, read) =
        decide_and_read(&serde_json::to_vec(&generic).unwrap(), head(None, None));
    assert!(matches!(disposition, AgentDisposition::Unlisted { .. }));
    assert_eq!(read, Some(generic));
    let notice = json!({"jsonrpc":"2.0","method":"SendMessage","params":params});
    assert!(matches!(
        decide_arrival(&serde_json::to_vec(&notice).unwrap(), head(None, None)),
        AgentDisposition::Notice { .. }
    ));
}

#[test]
fn the_media_type_is_judged_before_the_body_and_the_version() {
    let r = refused(decide_arrival(
        b"not json",
        head(Some("text/plain"), Some("9.9")),
    ));
    assert_eq!(r.status, 415);
    assert_eq!(r.code, CODE_CONTENT_TYPE_NOT_SUPPORTED);
    assert_eq!(r.id, None);
    assert_eq!(
        r.message,
        "this endpoint reads `application/json` and any `+json` media type; the request declared \
         `text/plain`"
    );
}

#[test]
fn a_json_media_type_in_any_spelling_is_read() {
    for ct in [
        "application/json",
        "Application/JSON; charset=utf-8",
        "application/a2a+json",
        "application/vnd.x+JSON ; q=1",
    ] {
        assert!(
            matches!(
                decide_arrival(SEND, head(Some(ct), None)),
                AgentDisposition::Request { .. }
            ),
            "{ct}"
        );
    }

    assert!(matches!(
        decide_arrival(SEND, head(None, None)),
        AgentDisposition::Request { .. }
    ));
}

#[test]
fn the_version_is_negotiated_on_major_minor_and_absent_is_0_3() {
    let version = |v: Option<&str>| match decide_arrival(SEND, head(None, v)) {
        AgentDisposition::Request { version, .. } => version,
        other => panic!("{other:?}"),
    };
    assert_eq!(version(None), "0.3");
    assert_eq!(version(Some("")), "0.3");
    assert_eq!(version(Some("  ")), "0.3");
    assert_eq!(version(Some("1.0")), "1.0");
    assert_eq!(version(Some("1.0.7")), "1.0");
    assert_eq!(version(Some(" 0.3 ")), "0.3");
    let r = refused(decide_arrival(SEND, head(None, Some(" 2.1 "))));
    assert_eq!(
        (r.status, r.code, r.id.clone()),
        (400, CODE_VERSION_NOT_SUPPORTED, None)
    );
    assert_eq!(
        r.message,
        "this endpoint speaks A2A 0.3 and 1.0; the request asked for `2.1`"
    );
}

#[test]
fn a_body_that_is_not_json_is_a_parse_refusal_with_no_id() {
    let r = refused(decide_arrival(b"{", head(None, None)));
    assert_eq!(
        r,
        AgentRefusal {
            status: 400,
            id: None,
            code: -32700,
            message: NOT_JSON.to_string(),
        }
    );
}

#[test]
fn an_envelope_the_reader_refuses_echoes_the_id_it_could_read() {
    let batch = refused(decide_arrival(b"[]", head(None, None)));
    assert_eq!((batch.status, batch.code, batch.id), (400, -32600, None));
    let wrong_version = refused(decide_arrival(
        br#"{"jsonrpc":"1.0","id":"a","method":"SendMessage"}"#,
        head(None, None),
    ));
    let invalid = busbar_contract::jsonrpc::read(&serde_json::json!(
        {"jsonrpc":"1.0","id":"a","method":"SendMessage"}
    ))
    .expect_err("the reader refuses it");
    assert_eq!(wrong_version.code, invalid.code);
    assert_eq!(wrong_version.message, invalid.message);
    assert_eq!(
        wrong_version.id,
        (!invalid.id.is_null()).then_some(invalid.id)
    );
}

#[test]
fn a_notification_is_acknowledged_and_never_answered() {
    assert_eq!(
        decide_arrival(
            br#"{"jsonrpc":"2.0","method":"SendMessage"}"#,
            head(None, None)
        ),
        AgentDisposition::Notice {
            method: "SendMessage".to_string()
        }
    );
}

#[test]
fn a_request_is_classed_by_its_row_and_an_unlisted_method_is_kept_verbatim() {
    match decide_arrival(SEND, head(None, Some("1.0"))) {
        AgentDisposition::Request { row, id, version } => {
            assert_eq!(row.op, crate::ops::OP_MESSAGE_SEND);
            assert_eq!(id, serde_json::json!(7));
            assert_eq!(version, "1.0");
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(
        decide_arrival(
            br#"{"jsonrpc":"2.0","id":"x","method":"vendor/Thing"}"#,
            head(None, None)
        ),
        AgentDisposition::Unlisted {
            method: "vendor/Thing".to_string(),
            id: serde_json::json!("x"),
            version: "0.3",
        }
    );
}

#[test]
fn a_refused_arrivals_words_read_back_as_the_same_refusal() {
    for r in [
        AgentRefusal {
            status: 415,
            id: None,
            code: -32005,
            message: "m `x`".to_string(),
        },
        AgentRefusal {
            status: 400,
            id: Some(serde_json::json!("id-1")),
            code: -32600,
            message: "bad".to_string(),
        },
        AgentRefusal {
            status: 400,
            id: Some(serde_json::json!(3)),
            code: -32600,
            message: String::new(),
        },
    ] {
        assert_eq!(
            AgentRefusal::from_words(r.words().as_bytes()),
            Some(r.clone())
        );
    }
    assert_eq!(AgentRefusal::from_words(b"not the plane's words"), None);
    assert_eq!(AgentRefusal::from_words(br#"{"status":-1}"#), None);
}

#[test]
fn the_json_rpc_rendering_is_the_one_envelope_with_error_info_for_an_a2a_code() {
    let r = AgentRefusal {
        status: 415,
        id: None,
        code: -32005,
        message: "m".to_string(),
    };
    let out = render(Dialect::JsonRpc, &r, true);
    assert_eq!(out.status, 415);
    assert_eq!(out.content_type, "application/json");
    let doc: serde_json::Value = serde_json::from_slice(&out.body).expect("json");
    assert_eq!(
        doc,
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": null,
            "error": {
                "code": -32005,
                "message": "m",
                "data": [{
                    "@type": "type.googleapis.com/google.rpc.ErrorInfo",
                    "domain": "a2a-protocol.org",
                    "reason": "CONTENT_TYPE_NOT_SUPPORTED",
                }],
            },
        })
    );

    let parse = refused(decide_arrival(b"{", head(None, None)));
    let doc: serde_json::Value =
        serde_json::from_slice(&render(Dialect::JsonRpc, &parse, true).body).expect("json");
    assert!(doc["error"].get("data").is_none());
}

#[test]
fn the_rest_rendering_is_the_aip193_document() {
    let r = AgentRefusal {
        status: 400,
        id: Some(serde_json::json!(1)),
        code: -32009,
        message: "v".to_string(),
    };
    let doc: serde_json::Value =
        serde_json::from_slice(&render(Dialect::RestJson, &r, true).body).expect("json");
    assert_eq!(
        doc,
        serde_json::json!({"error": {
            "code": 400,
            "status": "UNIMPLEMENTED",
            "message": "v",
            "details": [{
                "@type": "type.googleapis.com/google.rpc.ErrorInfo",
                "domain": "a2a-protocol.org",
                "reason": "VERSION_NOT_SUPPORTED",
            }],
        }})
    );

    let odd = AgentRefusal {
        status: 429,
        id: None,
        code: -1,
        message: String::new(),
    };
    assert_eq!(odd.aip193()["error"]["status"], "RESOURCE_EXHAUSTED");
}

#[test]
fn a_kernel_refusal_keeps_the_kernels_status_and_is_worded_as_an_unsupported_operation() {
    let r = kernel_refusal(403, "this key may not reach that agent");
    let out = render(Dialect::JsonRpc, &r, false);
    assert_eq!(out.status, 0, "the kernel's status stands");
    let doc: serde_json::Value = serde_json::from_slice(&out.body).expect("json");
    assert_eq!(doc["id"], serde_json::Value::Null);
    assert_eq!(doc["error"]["code"], -32004);
    assert_eq!(doc["error"]["message"], "this key may not reach that agent");
    assert_eq!(doc["error"]["data"][0]["reason"], "UNSUPPORTED_OPERATION");
}

/// THE WORDS NEVER OVERFLOW THE ABI CAP (spec ruling log 2026-09-30, new-plane refusals follow
#[test]
fn the_words_of_a_head_refusal_echoing_the_largest_admitted_field_line_fit_the_abi_cap() {
    use busbar_contract::abi::plane::{LARGEST_ADMITTED_FIELD_LINE, MAX_REFUSAL_TEXT};
    let line = |name: &str, c: char| {
        c.to_string()
            .repeat(LARGEST_ADMITTED_FIELD_LINE as usize - name.len() - 2)
    };
    let (quotes, slashes) = (line(H_CONTENT_TYPE, '"'), line(H_VERSION, '\\'));
    for r in [
        refused(decide_arrival(b"", head(Some(&quotes), None))),
        refused(decide_arrival(b"", head(None, Some(&slashes)))),
    ] {
        let words = r.words();
        assert!(
            words.len() as u64 <= MAX_REFUSAL_TEXT,
            "{} > {MAX_REFUSAL_TEXT}",
            words.len()
        );
        assert_eq!(AgentRefusal::from_words(words.as_bytes()), Some(r));
    }
}

/// AN `Origin` IS JUDGED FIRST, as the engine's sequence judged it before every request-line rule:
#[test]
fn an_origin_that_is_not_loopback_is_refused_before_every_other_rule() {
    for origin in [
        "http://evil.example",
        "null",
        "file://x",
        "https://localhost.evil.example",
    ] {
        let r = refused(decide_arrival(
            b"not json",
            with_origin(Some(origin), Some("text/plain"), Some("9.9")),
        ));
        assert_eq!(
            r,
            AgentRefusal {
                status: STATUS_FORBIDDEN,
                id: None,
                code: CODE_UNSUPPORTED_OPERATION,
                message: ORIGIN_REFUSED.to_string(),
            },
            "{origin}"
        );
    }
    for origin in [
        "http://localhost",
        "http://127.0.0.1:8080",
        "https://[::1]:3000",
    ] {
        assert!(
            matches!(
                decide_arrival(SEND, with_origin(Some(origin), None, None)),
                AgentDisposition::Request { .. }
            ),
            "{origin}"
        );
    }
}

/// A METHOD THE VOCABULARY DOES NOT LIST IS RELAYED, NEVER REFUSED: classed as the hop the engine
#[test]
fn an_unlisted_method_is_classed_as_the_hop_the_engine_relays_it_on() {
    use crate::ops::{OP_MESSAGE_SEND, OP_MESSAGE_STREAM, OP_TASK_GET};
    for (method, op) in [
        ("vendor/Thing", OP_MESSAGE_SEND),
        ("Frobnicate", OP_MESSAGE_SEND),
        ("vendor/stream", OP_MESSAGE_STREAM),
        ("tasks/get", OP_TASK_GET),
    ] {
        let request = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{method}"}}"#);
        let notice = format!(r#"{{"jsonrpc":"2.0","method":"{method}"}}"#);
        for body in [request, notice] {
            assert_eq!(
                decide_arrival(body.as_bytes(), head(None, None)).op_class(),
                Some(op),
                "{body}"
            );
        }
    }
    assert_eq!(
        AgentDisposition::Refused(refused(decide_arrival(b"{", head(None, None)))).op_class(),
        None
    );
}

/// THE gRPC LINE'S RENDERING is the JSON-RPC envelope at the refusal's neutral status, the bytes
#[test]
fn the_grpc_rendering_is_the_envelope_at_the_neutral_status() {
    let own = refused(decide_arrival(b"", head(Some("text/plain"), None)));
    assert_eq!(
        render(Dialect::Framed, &own, true),
        render(Dialect::JsonRpc, &own, true)
    );
    assert_eq!(render(Dialect::Framed, &own, true).status, 415);
    let kernel = kernel_refusal(429, "this key's budget is spent");
    let out = render(Dialect::Framed, &kernel, false);
    assert_eq!(out.status, 0);
    assert_eq!(out, render(Dialect::JsonRpc, &kernel, false));
}

/// THE OPEN BREAKER'S REFUSAL is 1.5.5's `BreakerOpen` client text: `503`, `-32004`, the agent
#[test]
fn an_open_breaker_refusal_names_the_agent_and_the_seconds_to_wait() {
    let refusal = breaker_refusal("probe", Some(serde_json::json!(7)), 12);
    assert_eq!(refusal.status, 503);
    assert_eq!(refusal.code, CODE_UNSUPPORTED_OPERATION);
    assert_eq!(refusal.id, Some(serde_json::json!(7)));
    assert_eq!(
        refusal.message,
        "a2a.hop.breaker_open: agent `probe` is unavailable: its circuit breaker is open after \
         repeated backend failures; busbar did not dispatch this request. Retry after 12s"
    );
    let rendered = render(Dialect::JsonRpc, &refusal, true);
    assert_eq!(rendered.status, 503);
    let doc: serde_json::Value = serde_json::from_slice(&rendered.body).expect("json");
    assert_eq!(doc["id"], 7);
    assert_eq!(doc["error"]["code"], -32004);
}

/// A BREAKER REFUSAL NAMING ITS REJECTED TASK is the plain refusal plus the task's `ResourceInfo`
#[test]
fn a_breaker_refusal_names_the_task_it_rejected_on_every_line() {
    let refusal = breaker_refusal("probe", Some(serde_json::json!(7)), 12);
    let named = |doc: &serde_json::Value, at: &str| {
        doc.pointer(at)
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .any(|e| e["resourceType"] == "a2a.busbar/task" && e["resourceName"] == "task-1")
    };
    for (dialect, at) in [
        (Dialect::JsonRpc, "/error/data"),
        (Dialect::Framed, "/error/data"),
        (Dialect::RestJson, "/error/details"),
    ] {
        let plain: serde_json::Value =
            serde_json::from_slice(&render(dialect, &refusal, true).body).expect("json");
        assert!(
            !named(&plain, at),
            "{dialect:?}: the plain render names no task"
        );
        let rendered = render_about_task(dialect, &refusal, "task-1");
        assert_eq!(rendered.status, 503, "{dialect:?}");
        let doc: serde_json::Value = serde_json::from_slice(&rendered.body).expect("json");
        assert!(named(&doc, at), "{dialect:?}: {doc}");
    }
}

/// THE UNGRANTED CALLER is told the scope its grant does not reach, in 1.5.5's words.
#[test]
fn an_ungranted_caller_is_told_the_scope_it_does_not_hold() {
    assert_eq!(
        not_granted_sentence("agent:probe"),
        "this key is not granted `agent:probe`"
    );
}

/// A KEY THAT IS NOT LIVE IS REFUSED `401`, HOWEVER IT IS NOT LIVE (1.5.5's `KeyNotLive`). Which
#[test]
fn a_key_that_is_not_live_is_refused_401_however_it_is_not_live() {
    let refusal = not_live();
    let rendered = render(Dialect::JsonRpc, &refusal, true);
    assert_eq!(rendered.status, 401);
    let doc: serde_json::Value = serde_json::from_slice(&rendered.body).expect("json");
    assert_eq!(doc["error"]["code"], -32004);
    assert_eq!(doc["error"]["message"], "this key is not live");
    assert_eq!(doc["id"], serde_json::Value::Null);
}

/// AN AGENT THIS DEPLOYMENT DOES NOT FRONT is a `404` in 1.5.5's words (`NoSuchAgent`), never an
#[test]
fn an_unknown_agent_is_a_404_in_1_5_5_words() {
    let rendered = render(Dialect::JsonRpc, &no_such_agent("nonexistent"), true);
    assert_eq!(rendered.status, 404);
    let doc: serde_json::Value = serde_json::from_slice(&rendered.body).expect("json");
    assert_eq!(doc["error"]["code"], -32004);
    assert_eq!(doc["error"]["message"], "no fronted agent `nonexistent`");
    assert_eq!(doc["id"], serde_json::Value::Null);
}

/// A request with `"id": null` is never answered with a success: it is an Invalid Request (`-32600`)
#[test]
fn a_null_id_is_never_answered_with_a_success_result() {
    let body = br#"{"jsonrpc":"2.0","id":null,"method":"SendMessage","params":{}}"#;
    let disposition = decide_arrival(body, head(None, None));
    assert_eq!(
        disposition.op_class(),
        None,
        "a refused arrival is never routed, so nothing is relayed to a backend"
    );
    let r = refused(disposition);
    assert_eq!(r.status, 400, "not a 200");
    assert_eq!(r.code, -32600, "an illegal `id` is an Invalid Request");
    assert_eq!(r.id, None);
    let body = render(Dialect::JsonRpc, &r, true);
    assert_eq!(body.status, 400);
    let doc: serde_json::Value = serde_json::from_slice(&body.body).unwrap();
    assert!(doc.get("result").is_none(), "{doc}");
    assert_eq!(doc.pointer("/error/code"), Some(&serde_json::json!(-32600)));
    assert_eq!(
        doc.get("id"),
        Some(&serde_json::Value::Null),
        "the refusal must carry `\"id\": null`: {doc}"
    );
}

/// A request method with no `id` member is a notification: acknowledged, never answered (JSON-RPC
#[test]
fn a_request_method_with_no_id_is_a_notification_and_gets_no_response_body() {
    let d = decide_arrival(
        br#"{"jsonrpc":"2.0","method":"SendMessage","params":{}}"#,
        head(None, None),
    );
    assert_eq!(
        d,
        AgentDisposition::Notice {
            method: "SendMessage".to_string()
        }
    );
    assert!(
        d.op_class().is_some(),
        "an admitted notification is a unit of its method's class"
    );
    assert_eq!(
        STATUS_ACCEPTED, 202,
        "a notification is acknowledged, not answered"
    );
}

/// A tripped agent rejects a fresh submission on each line with 503 and `-32004`, naming the agent
#[test]
fn a_tripped_agent_rejects_fresh_submissions_on_every_binding() {
    let refusal = breaker_refusal("planner", Some(serde_json::json!(1)), 30);
    let rpc = render(Dialect::JsonRpc, &refusal, true);
    assert_eq!(rpc.status, 503);
    let doc: serde_json::Value = serde_json::from_slice(&rpc.body).unwrap();
    assert_eq!(doc["error"]["code"], -32004);
    assert!(doc["error"]["message"]
        .as_str()
        .unwrap()
        .contains("Retry after 30s"));
    assert!(doc.get("result").is_none());

    let rest = render(Dialect::RestJson, &refusal, true);
    assert_eq!(rest.status, 503);
    let doc: serde_json::Value = serde_json::from_slice(&rest.body).unwrap();
    assert_eq!(doc["error"]["code"], 503);
    assert!(doc["error"]["message"]
        .as_str()
        .unwrap()
        .contains("breaker_open"));

    let framed = render(Dialect::Framed, &refusal, true);
    assert_eq!(framed.status, 503);
    let reply = crate::framed::refusal(&framed.body, framed.status);
    assert_eq!(reply.code, crate::framed::Code::Unavailable as u32);
    assert!(String::from_utf8_lossy(&reply.body).contains("breaker_open"));
    assert!(String::from_utf8_lossy(&reply.body).contains("Retry after 30s"));
    let trailers = crate::framed::status_block(&reply);
    assert!(String::from_utf8_lossy(&trailers).contains("grpc-status: 14\r\n"));
}

/// Only node faults use the internal refusal class; each refusal class has one consistent answer.
#[test]
fn p_item_refusal_reason_collapse_only_a_node_fault_is_internal_and_one_class_one_answer() {
    use busbar_contract::abi::plane::{RefusalClass, RefusalCode};
    let words = "the kernel's words";
    let mut answers: Vec<(RefusalClass, Vec<(u32, serde_json::Value)>)> = Vec::new();
    for &code in RefusalCode::ALL {
        let class = code.class();
        let refusal = kernel_refusal_of(code.code(), 500, words);
        let lines: Vec<(u32, serde_json::Value)> =
            [Dialect::JsonRpc, Dialect::RestJson, Dialect::Framed]
                .into_iter()
                .map(|dialect| {
                    let out = render(dialect, &refusal, false);
                    let doc = serde_json::from_slice(&out.body).expect("a JSON document");
                    (out.status, doc)
                })
                .collect();
        let rpc = &lines[0].1;
        assert_eq!(lines[0].0, 0, "{code:?}: the kernel's status stands");
        assert_eq!(
            rpc["error"]["message"], words,
            "{code:?}: the kernel's words"
        );
        assert_eq!(
            rpc["error"]["code"] == crate::agent_arrival::CODE_INTERNAL,
            class.is_node_fault(),
            "{code:?} (class {class:?}) renders {rpc}"
        );
        match answers.iter().find(|(c, _)| *c == class) {
            Some((_, first)) => assert_eq!(
                *first, lines,
                "{code:?} answers differently from the rest of {class:?}"
            ),
            None => answers.push((class, lines)),
        }
    }
    assert_eq!(
        answers.len(),
        RefusalClass::ALL.len(),
        "every class is some reason's"
    );

    assert_eq!(
        kernel_refusal_of(u32::MAX, 500, words),
        kernel_refusal(500, words)
    );
}

#[test]
fn near_miss_versions_and_media_types_are_refused_before_dispatch() {
    for version in ["1.1", "0.2", "0.4", "3.0"] {
        let answer = refused(decide_arrival(SEND, head(None, Some(version))));
        assert_eq!(
            (answer.status, answer.code),
            (400, CODE_VERSION_NOT_SUPPORTED)
        );
    }
    for content_type in [
        "application/jsonl",
        "application/x-ndjson",
        "application/json-seq",
        "text/json",
        "application/vnd.x+jsonx",
    ] {
        let answer = refused(decide_arrival(SEND, head(Some(content_type), None)));
        assert_eq!(
            (answer.status, answer.code),
            (415, CODE_CONTENT_TYPE_NOT_SUPPORTED)
        );
    }
}
