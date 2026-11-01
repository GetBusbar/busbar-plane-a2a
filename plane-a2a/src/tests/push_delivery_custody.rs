// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
use super::*;

fn registered(url: &str, credential: &str) -> PushConfig {
    config(
        url,
        Some(DeliveryAuth {
            scheme: "Bearer".into(),
            credentials: busbar_contract::abi::sdk::test_support::chip::cred(credential),
        }),
    )
}
fn auth_head(head: &[u8], credential: &[u8]) -> bool {
    head.windows(credential.len()).any(|w| w == credential)
}

#[test]
fn a_retry_keeps_the_credential_registered_with_its_original_url() {
    let mut book = Book::default();
    let row = moved(&mut book, "");
    let deliveries = Deliveries::default();
    queue(
        &deliveries,
        &row,
        Some(&registered("https://one.example/cb", "one-secret")),
    );
    let mut host = TestHost::answering(vec![Some((DEST_ALLOWED, &[AT_REGISTRATION][..]))], 503);
    let attempting = Attempting::default();
    assert_eq!(
        tick_over(&mut host, &deliveries, &attempting, 1),
        Outcome::Ready
    );
    queue(
        &deliveries,
        &row,
        Some(&registered("https://two.example/cb", "two-secret")),
    );
    let retry = deliveries.next_tick_ns();
    host.status = 200;
    assert_eq!(
        tick_over(&mut host, &deliveries, &attempting, retry),
        Outcome::Ready
    );
    assert_eq!(
        host.sent,
        ["https://one.example/cb", "https://one.example/cb"]
    );
    assert!(auth_head(&host.heads[1], b"Bearer one-secret"));
    assert!(!auth_head(&host.heads[1], b"two-secret"));
    assert_eq!(
        tick_over(&mut host, &deliveries, &attempting, retry),
        Outcome::Ready
    );
    assert_eq!(
        host.sent.last().map(String::as_str),
        Some("https://two.example/cb")
    );
    assert!(auth_head(host.heads.last().unwrap(), b"Bearer two-secret"));
}

#[test]
fn deleting_a_config_stops_its_pending_attempt_and_keeps_another_tasks_delivery() {
    let mut book = Book::default();
    let mut row = moved(&mut book, "");
    let deliveries = Deliveries::default();
    queue(
        &deliveries,
        &row,
        Some(&registered(
            "https://registered.example/cb",
            "registered-secret",
        )),
    );
    let mut host = TestHost::answering(vec![Some((DEST_ALLOWED, &[AT_REGISTRATION][..]))], 200);
    host.pends = 1;
    let attempting = Attempting::default();
    assert_eq!(
        tick_over(&mut host, &deliveries, &attempting, 1),
        Outcome::Pending
    );
    row.task_id = "t2".into();
    queue(
        &deliveries,
        &row,
        Some(&config("https://inline.example/cb", None)),
    );
    forget_deleted(
        &deliveries,
        &[Write {
            kind: KIND_PUSH_CONFIG,
            key: task_key(ALICE, "t1"),
            value: Vec::new(),
        }],
    );
    assert_eq!(
        drive_over(&mut host, &deliveries, &attempting),
        Outcome::Ready
    );
    assert!(
        host.sent.is_empty(),
        "deleted config must not finish a pending send"
    );
    assert_eq!(host.abandoned, 1);
    assert_eq!(
        tick_over(&mut host, &deliveries, &attempting, 2),
        Outcome::Ready
    );
    assert_eq!(host.sent, ["https://inline.example/cb"]);
    assert!(!auth_head(&host.heads[0], b"registered-secret"));
}

#[test]
fn a_failed_destination_service_retries_without_sending() {
    let deliveries = queued("https://hook.example/cb");
    let mut host = TestHost::answering(vec![None], 200);
    let attempting = Attempting::default();
    assert_eq!(
        tick_over(&mut host, &deliveries, &attempting, 1),
        Outcome::Ready
    );
    assert!(host.sent.is_empty());
    assert!(
        deliveries.next_tick_ns() > 1,
        "service fault retains retry intent"
    );
    host.verdicts = vec![Some((DEST_ALLOWED, vec![AT_REGISTRATION.into()]))];
    let retry = deliveries.next_tick_ns();
    assert_eq!(
        tick_over(&mut host, &deliveries, &attempting, retry),
        Outcome::Ready
    );
    assert_eq!(host.sent, ["https://hook.example/cb"]);
}

#[test]
fn a_legacy_row_url_without_a_durable_config_never_reconstructs_authority() {
    let mut book = Book::default();
    let row = moved(&mut book, "https://legacy.example/cb");
    let deliveries = Deliveries::default();
    assert!(!queue_moved(&deliveries, &mut book, ALICE, &row).unwrap());
    assert!(deliveries.next_due(0).is_none());
}

struct UnavailableConfig;
impl Records for UnavailableConfig {
    fn get(&mut self, _: &str, _: &str) -> Result<Option<Vec<u8>>, Halt> {
        Err(Halt::Failed("store unavailable".into()))
    }
    fn list(&mut self, _: &str, _: &str) -> Result<Vec<(String, Vec<u8>)>, Halt> {
        panic!("config is one record read")
    }
    fn claim(&mut self, _: &str, _: &str, _: u64) -> Result<bool, Halt> {
        panic!("queueing cannot mutate the task")
    }
}
#[test]
fn failed_configuration_read_retains_notification_intent_for_the_driver() {
    let mut book = Book::default();
    let row = moved(&mut book, "");
    let deliveries = Deliveries::default();
    assert!(
        queue_moved(&deliveries, &mut UnavailableConfig, ALICE, &row).unwrap(),
        "accepted move must retain its notification intent"
    );
    assert!(
        deliveries.next_tick_ns() > 0,
        "retained intent must be scheduled"
    );
    forget_deleted(
        &deliveries,
        &[Write {
            kind: KIND_PUSH_CONFIG,
            key: task_key(ALICE, "t1"),
            value: Vec::new(),
        }],
    );
    assert!(
        deliveries.next_due(0).is_none(),
        "delete must also remove unresolved intent"
    );
}
