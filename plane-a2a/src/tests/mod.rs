// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The crate's tests that reach past [`crate::door`]: once integration tests (`tests/*.rs`), now
//! in-crate because the crate's only public item is the door.

mod callback_custody;
pub(crate) mod capture;
mod codec_custody_cases;
mod conformance;
mod door_facts;
mod purity;
pub(crate) mod raw_custody_probe;
mod request_borrow_cases;
pub(crate) mod request_custody_probe;
