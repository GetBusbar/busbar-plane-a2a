// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PUBLISHED CONFORMANCE SUITE, run over this plane (OWNER 2026-10-03: plugins test themselves
//! against busbar's published suite). The linked door (`agent_door::door`) and this crate's
//! dropped-in image (the `busbar-plane-a2a-plugin` cdylib, which `cargo test` builds beside the
//! test), each through the one loader, driven by busbar-plugin-loader's plane script over
//! `conformance.json`, every step at its pinned crossing count, the two folds equal. This is the
//! plugin's own both-ways witness at the path every plugin repo keeps it (`tests/conformance.rs`).
//! `plugin-ci.yml` runs it under `--release`. The op-by-op script the crate carried in busbar is
//! `tests/both_ways.rs`.

busbar_plugin_loader::conformance_suite! {
    door: busbar_plane_a2a::agent_door::door,
    cdylib: "busbar_plane_a2a_plugin",
    inputs: include_str!("conformance.json"),
}
