// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::abi::mechanism::door::DoorFn;

pub(super) use busbar_test_kit::root_door_fixtures::piece_pending::Watching;

/// Keep the real linked door and its macro-origin proof paired at the test-kit boundary.
pub(super) fn select(selected: DoorFn) -> DoorFn {
    busbar_test_kit::root_door_fixtures::piece_pending::select(
        busbar_plane_a2a::MACRO_DOOR,
        selected,
    )
}
