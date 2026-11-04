// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Test-only builders for custody-owned generated messages.

use super::{Guard, Wipe};

/// Build test messages without moving unnamed fields out of a Drop-bearing default value.
pub(crate) fn initialized<T: Wipe + Default>(initialize: impl FnOnce(&mut T)) -> T {
    let mut value = Guard::new(T::default());
    initialize(&mut value);
    value.take()
}
