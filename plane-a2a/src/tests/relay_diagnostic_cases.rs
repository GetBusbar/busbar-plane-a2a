// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[test]
fn local_relay_refusals_explain_the_agent_and_keep_request_values_out_of_diagnostics() {
    for task in [false, true] {
        for cause in [
            "demoted",
            "credential",
            "binding",
            "http",
            "grpc",
            "grpc-method",
        ] {
            let mut hop = if task { task_sent(false) } else { sent() };
            hop.name_backend("diagnostic-agent", URL);
            let secret = "request-secret-must-not-be-journaled";
            let (reply, lines) = journaled(|| match cause {
                "demoted" => match hop.refuse_demoted() {
                    PieceAnswer::ToCaller(reply) => reply,
                    other => panic!("{other:?}"),
                },
                "credential" => hop.refuse_credential().0,
                "binding" => match hop.refuse_unspeakable("unsupported") {
                    PieceAnswer::ToCaller(reply) => reply,
                    other => panic!("{other:?}"),
                },
                _ => {
                    let (binding, method, params) = match cause {
                        "http" => (
                            Binding::HttpJson,
                            "GetTask",
                            json!({"id":false, "extra":secret}),
                        ),
                        "grpc" => (
                            Binding::Grpc,
                            "SendMessage",
                            json!({"message":{"role":secret}}),
                        ),
                        _ => (Binding::Grpc, "vendor/Unknown", json!({"secret":secret})),
                    };
                    hop.bind(binding, &json!({"method":method, "params":params}));
                    match hop.on_piece(kernel(Some(URL))) {
                        PieceAnswer::ToCaller(reply) => reply,
                        other => panic!("{other:?}"),
                    }
                }
            });
            assert!(reply.status >= 400, "{cause}: {reply:?}");
            let banner = crate::diagnostics::A2A_RELAYED_SUBMISSION_FAILED
                .banner()
                .to_string();
            let line = lines
                .iter()
                .find(|(_, line)| line.contains(&banner))
                .unwrap_or_else(|| panic!("{cause}: no operator diagnostic: {lines:?}"));
            assert!(line.1.contains("diagnostic-agent"), "{cause}: {line:?}");
            assert!(line.1.contains("error="), "{cause}: {line:?}");
            assert!(lines.iter().all(|(_, line)| !line.contains(secret)));
            assert!(!String::from_utf8_lossy(&reply.body).contains("vendor.example"));
        }
    }
}
