// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! Held-source fixtures for the deferred read seam; public-route regression lives separately.
use super::*;

struct ConfigLine<'a> {
    deliveries: &'a Deliveries,
    host: TestHost,
    first: bool,
    delete_on_ready: bool,
}
impl Line for ConfigLine<'_> {
    fn config(&mut self, row: &TaskRow) -> Result<Option<PushConfig>, Halt> {
        if self.first {
            self.first = false;
            return Err(Halt::Pending);
        }
        if self.delete_on_ready {
            self.deliveries.forget_task(&row.task_id);
        }
        Ok(Some(config("https://receiver.example/cb", None)))
    }
    fn judge(&mut self, url: &str) -> Poll<Option<Judgement>> {
        self.host.judge(url)
    }
    fn send(&mut self, ex: &mut Exchange, url: &str) -> Poll<Option<u16>> {
        self.host.send(ex, url)
    }
    fn jitter(&mut self) -> u8 {
        self.host.jitter()
    }
    fn abandon(&mut self, stream: Option<u64>) {
        self.host.abandon(stream)
    }
}
#[test]
fn deletion_during_resumed_config_resolution_releases_driver_holding() {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    let mut book = Book::default();
    let row = moved(&mut book, "");
    let deliveries = Deliveries::default();
    defer(&deliveries, &row);
    let attempting = Attempting::default();
    let mut line = ConfigLine {
        deliveries: &deliveries,
        host: TestHost::answering(vec![Some((DEST_ALLOWED, &[AT_REGISTRATION][..]))], 200),
        first: true,
        delete_on_ready: true,
    };
    assert_eq!(
        tick_over(&mut line, &deliveries, &attempting, 1),
        Outcome::Pending
    );
    assert_eq!(
        drive_over(&mut line, &deliveries, &attempting),
        Outcome::Ready
    );
    assert!(attempting.started_ns().is_none());
    assert!(line.host.sent.is_empty());
    let count = Arc::new(AtomicUsize::new(0));
    let captured = count.clone();
    deliveries.arm(move || {
        Box::new(move || {
            captured.fetch_add(1, Ordering::SeqCst);
        })
    });
    queue(
        &deliveries,
        &row,
        Some(&config("https://next.example/cb", None)),
    );
    assert_eq!(
        count.load(Ordering::SeqCst),
        1,
        "subsequent work must wake after deletion wins resolution"
    );
}
