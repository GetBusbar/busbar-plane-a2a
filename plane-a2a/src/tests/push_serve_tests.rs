// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
use super::*;

#[test]
fn every_unauthorized_push_refusal_challenges_bearer_authentication() {
    assert!(refusal_fields(401, &[]).contains(&("www-authenticate", "Bearer")));
    assert!(!refusal_fields(400, &[])
        .iter()
        .any(|(name, _)| *name == "www-authenticate"));
}
