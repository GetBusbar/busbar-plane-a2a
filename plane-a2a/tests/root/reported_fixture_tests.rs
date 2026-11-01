// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
use super::*;

#[test]
fn client_identity_files_are_unique_for_repeated_names() {
    rig::install_crypto_provider();
    let first = client_identity_files("repeated-identity-fixture", "planner");
    let cert = std::fs::read(&first.1).unwrap();
    let key = std::fs::read(&first.2).unwrap();
    let second = client_identity_files("repeated-identity-fixture", "planner");
    // Also cleans the old tuple-only fixture after the regression panics.
    struct Cleanup(Vec<String>);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            for path in &self.0 {
                let _ = std::fs::remove_file(path);
            }
        }
    }
    let _cleanup = Cleanup(vec![
        first.1.clone(),
        first.2.clone(),
        second.1.clone(),
        second.2.clone(),
    ]);
    assert_ne!(first.1, second.1);
    assert_ne!(first.2, second.2);
    assert_eq!(std::fs::read(&first.1).unwrap(), cert);
    assert_eq!(std::fs::read(&first.2).unwrap(), key);
}
