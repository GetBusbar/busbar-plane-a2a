// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Custody wipes: a wiped container is drained, so the Drops of its owners do not wipe it again.

use std::cell::Cell;

use super::Wipe;

thread_local! { static WIPES: Cell<usize> = const { Cell::new(0) }; }

/// A Drop-bearing node that wipes its children, as the generated messages and `wkt` values do.
struct Node(Vec<Node>);

impl Wipe for Node {
    fn wipe(&mut self) {
        WIPES.with(|w| w.set(w.get() + 1));
        self.0.wipe();
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        self.wipe();
    }
}

#[test]
fn dropping_a_deep_list_wipes_each_node_a_bounded_number_of_times() {
    const DEPTH: usize = 64;
    let mut root = Node(Vec::new());
    for _ in 1..DEPTH {
        root = Node(vec![root]);
    }
    WIPES.with(|w| w.set(0));
    drop(root);
    let wipes = WIPES.with(Cell::get);
    assert!(
        wipes <= 2 * DEPTH,
        "{wipes} wipes for {DEPTH} nodes: each ancestor's Drop re-wipes the subtree"
    );
}
