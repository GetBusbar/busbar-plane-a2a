// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `a2a` plane as a droppable busbar plugin: the `cdylib` a signed tarball carries

#![deny(unsafe_code)]

/// The exported door: the macro's `#[unsafe(no_mangle)]` symbol is the one exemption.
#[allow(unsafe_code)]
mod exported {
    busbar_contract::export_door!(busbar_plane_a2a::door);
}
