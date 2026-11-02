// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::abi::host::conn::connector::{CAUSE_CONNECT, CAUSE_DEADLINE};
use busbar_contract::abi::sdk::conn::ConnFailure;

fn urls() -> [String; 2] {
    crate::card_trust::discovery_urls("https://agent.example:8443/tasks").unwrap()
}

fn plain(message: &str) -> CardRefusal {
    CardRefusal {
        message: message.to_string(),
        transport: None,
    }
}

fn transport(url: &str, redirects: u8, cause: u64, failure: ConnFailure) -> CardRefusal {
    CardRefusal {
        message: crate::card_trust::read_card(
            url,
            Err(crate::card_trust::transport_err(cause, &failure)),
        )
        .unwrap_err(),
        transport: Some(CardTransportRefusal {
            url: url.to_string(),
            redirects,
            cause,
            failure,
        }),
    }
}

fn combined(canonical: &CardRefusal, legacy: &CardRefusal) -> String {
    format!("{}; the legacy path: {}", canonical.message, legacy.message)
}

#[test]
fn identical_nontransport_refusals_are_said_once() {
    let why = "the card redirect limit was exceeded at the same final target";
    assert_eq!(card_refusals(plain(why), plain(why), &urls()), why);
}

#[test]
fn distinct_nontransport_refusals_keep_both_reasons() {
    let first = plain("the canonical card destination was refused as loopback");
    let second = plain("the legacy card destination could not be resolved");
    let want = combined(&first, &second);
    assert_eq!(card_refusals(first, second, &urls()), want);
}

#[test]
fn the_same_direct_transport_failure_keeps_the_legacy_failure_words() {
    let paths = urls();
    let first = transport(
        &paths[0],
        0,
        CAUSE_CONNECT,
        ConnFailure::Failed("connection refused".into()),
    );
    let second = transport(
        &paths[1],
        0,
        CAUSE_CONNECT,
        ConnFailure::Failed("connection refused".into()),
    );
    let want = second.message.clone();
    assert_eq!(card_refusals(first, second, &paths), want);
}

#[test]
fn equal_display_does_not_hide_distinct_failure_variants_or_numeric_causes() {
    let paths = urls();
    for (first_cause, first_failure, second_cause, second_failure) in [
        (
            0,
            ConnFailure::Failed("same".into()),
            0,
            ConnFailure::Refused("same".into()),
        ),
        (
            0,
            ConnFailure::Failed("same".into()),
            u64::MAX,
            ConnFailure::Failed("same".into()),
        ),
        (
            CAUSE_DEADLINE,
            ConnFailure::Failed("first".into()),
            CAUSE_DEADLINE,
            ConnFailure::Failed("second".into()),
        ),
    ] {
        assert_eq!(
            crate::card_trust::transport_err(first_cause, &first_failure),
            crate::card_trust::transport_err(second_cause, &second_failure),
            "these are genuine display collisions"
        );
        let first = transport(&paths[0], 0, first_cause, first_failure);
        let second = transport(&paths[1], 0, second_cause, second_failure);
        let want = combined(&first, &second);
        assert_eq!(card_refusals(first, second, &paths), want);
    }
}

#[test]
fn equal_messages_after_both_paths_redirect_to_one_target_keep_both_failures() {
    let paths = urls();
    let target = "https://elsewhere.example/card";
    let first = transport(
        target,
        1,
        CAUSE_CONNECT,
        ConnFailure::Failed("closed".into()),
    );
    let second = transport(
        target,
        1,
        CAUSE_CONNECT,
        ConnFailure::Failed("closed".into()),
    );
    assert_eq!(first.message, second.message);
    let want = combined(&first, &second);
    assert_eq!(card_refusals(first, second, &paths), want);
}

#[test]
fn a_redirect_back_to_the_original_target_is_not_a_direct_failure() {
    let paths = urls();
    for (first_redirects, second_redirects) in [(1, 0), (0, 1), (1, 1)] {
        let first = transport(
            &paths[0],
            first_redirects,
            CAUSE_CONNECT,
            ConnFailure::Failed("closed".into()),
        );
        let second = transport(
            &paths[1],
            second_redirects,
            CAUSE_CONNECT,
            ConnFailure::Failed("closed".into()),
        );
        let want = combined(&first, &second);
        assert_eq!(card_refusals(first, second, &paths), want);
    }
}

#[test]
fn transport_failures_at_other_hosts_or_paths_keep_both_reasons() {
    let paths = urls();
    for target in [
        "https://elsewhere.example:8443/.well-known/agent-card.json",
        "https://agent.example:8443/other-card",
    ] {
        let first = transport(
            target,
            0,
            CAUSE_CONNECT,
            ConnFailure::Failed("closed".into()),
        );
        let second = transport(
            &paths[1],
            0,
            CAUSE_CONNECT,
            ConnFailure::Failed("closed".into()),
        );
        let want = combined(&first, &second);
        assert_eq!(card_refusals(first, second, &paths), want);
    }
}

#[test]
fn even_an_expected_pair_cannot_coalesce_across_origins() {
    let paths = [
        "https://one.example/.well-known/agent-card.json".to_string(),
        "https://two.example/.well-known/agent.json".to_string(),
    ];
    let first = transport(
        &paths[0],
        0,
        CAUSE_CONNECT,
        ConnFailure::Failed("closed".into()),
    );
    let second = transport(
        &paths[1],
        0,
        CAUSE_CONNECT,
        ConnFailure::Failed("closed".into()),
    );
    let want = combined(&first, &second);
    assert_eq!(card_refusals(first, second, &paths), want);
}

#[test]
fn a_transport_and_nontransport_refusal_never_coalesce_even_when_the_words_match() {
    let paths = urls();
    let first = transport(
        &paths[0],
        0,
        CAUSE_CONNECT,
        ConnFailure::Failed("closed".into()),
    );
    let second = plain(&first.message);
    let want = combined(&first, &second);
    assert_eq!(card_refusals(first, second, &paths), want);
}
