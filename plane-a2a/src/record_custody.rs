// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Plane-owned copies of conditional record bytes keep custody independently of the host.

use busbar_contract::abi::sdk::plane::conditional as wire;
use busbar_contract::abi::sdk::store::conditional::Expected;

use crate::proto::custody::Wipe;

/// Retire an initialized byte allocation through the same owner as relayed wire buffers.
pub(crate) fn bytes(value: &mut Vec<u8>) {
    drop(crate::relay::RawBytes::from(std::mem::take(value)));
}

impl Wipe for Expected {
    fn wipe(&mut self) {
        if let Self::Bytes(value) = self {
            bytes(value);
        }
    }
}

impl Wipe for wire::RecordPredicate {
    fn wipe(&mut self) {
        bytes(&mut self.key);
        self.expected.wipe();
    }
}

impl Wipe for wire::RecordMutation {
    fn wipe(&mut self) {
        match self {
            Self::Put { key, value, .. } => {
                bytes(key);
                bytes(value);
            }
            Self::Delete { key, .. } => bytes(key),
        }
    }
}

impl Wipe for wire::ChainMutation {
    fn wipe(&mut self) {
        match self {
            Self::Check { scope, life, .. } | Self::Drop { scope, life, .. } => {
                bytes(scope);
                life.wipe();
            }
            Self::Append {
                scope,
                life,
                content,
                ..
            } => {
                bytes(scope);
                life.wipe();
                bytes(content);
            }
        }
    }
}

impl Wipe for wire::Request {
    fn wipe(&mut self) {
        self.candidate.predicates.wipe();
        self.candidate.mutations.wipe();
        self.candidate.chains.wipe();
    }
}
