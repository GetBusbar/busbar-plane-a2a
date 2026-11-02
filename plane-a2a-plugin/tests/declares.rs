// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DECLARES RIDE THE STATEMENT (ARCHITECT ruling 2026-10-21; BUSBAR-1.6.0.md l.246): the door's

#[test]
fn the_statement_states_the_whole_declares_document() {
    let row = busbar_plugin_loader::dispatch::LinkedRow::of_loaded(loaded_door()).unwrap();
    let read = busbar_contract::abi::mechanism::rendering::read(&row.statement).unwrap();
    assert_eq!(
        busbar_contract::abi::mechanism::extensions::declares(&read.extensions.bytes),
        Some(&include_bytes!("../../plane-a2a/declares.json")[..]),
    );
}

/// This plugin's own door, named for the loader.
fn loaded_door() -> busbar_plugin_loader::dispatch::LoadedDoor {
    busbar_plugin_loader::dispatch::LoadedDoor::from(
        busbar_plane_a2a::door as busbar_contract::abi::mechanism::door::DoorFn,
    )
}
