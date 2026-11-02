// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[test]
fn withdrawing_a_config_wakes_outside_the_callback_registry_lock() {
    let deliveries = Arc::new(Deliveries::default());
    let weak = Arc::downgrade(&deliveries);
    let (sent, heard) = std::sync::mpsc::channel();
    deliveries.arm(|| {
        Box::new(move || {
            let deliveries = weak.upgrade().expect("the withdrawing owner is live");

            deliveries.arm(|| panic!("the existing registration must be retained"));
            sent.send(()).unwrap();
        })
    });
    let worker = std::thread::spawn(move || deliveries.forget_task("withdrawn"));
    heard
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("the wake must permit reentry without its registry mutex held");
    worker.join().unwrap();
}
