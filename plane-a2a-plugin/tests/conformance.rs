// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Runs the published conformance suite for the A2A plane.

busbar_test_kit::conformance_suite! {
    door: busbar_plane_a2a::door,
    cdylib: "busbar_plane_a2a_plugin",
    inputs: include_str!("conformance.json"),
}
