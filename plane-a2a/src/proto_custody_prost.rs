// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The ordinary prost API with scoped replacements for owned string, bytes and map merge.
//!
//! The map entry delegates framing, recursion and field dispatch to prost::message::merge.
//! No second protobuf parser is involved. Encoding remains prost's own implementation.

pub(crate) use ::prost::*;

use super::Wipe;

pub(crate) trait MapValue: Default + Wipe + Send + Sync {
    fn merge_value(
        wire: ::prost::encoding::WireType,
        value: &mut Self,
        buf: &mut impl ::prost::bytes::Buf,
        ctx: ::prost::encoding::DecodeContext,
    ) -> Result<(), ::prost::DecodeError>;
}

impl MapValue for String {
    fn merge_value(
        wire: ::prost::encoding::WireType,
        value: &mut Self,
        buf: &mut impl ::prost::bytes::Buf,
        ctx: ::prost::encoding::DecodeContext,
    ) -> Result<(), ::prost::DecodeError> {
        encoding::string::merge(wire, value, buf, ctx)
    }
}

pub(crate) mod encoding {
    pub(crate) use ::prost::encoding::*;

    pub(crate) mod bytes {
        use super::*;
        use crate::proto::custody::{Guard, Wipe};
        pub(crate) use ::prost::encoding::bytes::{
            encode, encode_repeated, encoded_len, encoded_len_repeated,
        };

        pub(crate) fn merge(
            wire: WireType,
            value: &mut Vec<u8>,
            buf: &mut impl ::prost::bytes::Buf,
            ctx: DecodeContext,
        ) -> Result<(), ::prost::DecodeError> {
            let mut incoming = Guard::new(Vec::new());
            check_wire_type(WireType::LengthDelimited, wire)?;
            let len = decode_varint(buf)?;
            if len > buf.remaining() as u64 {
                // Exact prost length-delimited underflow diagnostic.
                const UNDERFLOW: &str = "buffer underflow";
                return Err(::prost::DecodeError::new(UNDERFLOW));
            }
            // Copy directly into initialized, exactly sized storage. Native bytes::merge's
            // copy_to_bytes intermediate can itself own a temporary allocation of secret bytes.
            incoming.resize(len as usize, 0);
            buf.copy_to_slice(&mut incoming);
            value.wipe();
            *value = incoming.take();
            Ok(())
        }

        pub(crate) fn merge_repeated(
            wire: WireType,
            values: &mut Vec<Vec<u8>>,
            buf: &mut impl ::prost::bytes::Buf,
            ctx: DecodeContext,
        ) -> Result<(), ::prost::DecodeError> {
            let mut value = Guard::new(Vec::new());
            merge(wire, &mut value, buf, ctx)?;
            values.push(value.take());
            Ok(())
        }
    }

    pub(crate) mod string {
        use super::*;
        use crate::proto::custody::{Guard, Wipe};
        pub(crate) use ::prost::encoding::string::{
            encode, encode_repeated, encoded_len, encoded_len_repeated,
        };

        /// Exact prost invalid-UTF8 diagnostic, retained across its safe ownership adapter.
        const INVALID_UTF8: &str = "invalid string value: data is not UTF-8 encoded";

        pub(crate) fn merge(
            wire: WireType,
            value: &mut String,
            buf: &mut impl ::prost::bytes::Buf,
            ctx: DecodeContext,
        ) -> Result<(), ::prost::DecodeError> {
            let mut incoming = Guard::new(Vec::new());
            // Prost clears the destination String on every merge error. Wipe before matching that
            // state transition, so an invalid length or UTF8 never hides its initialized old bytes.
            value.wipe();
            value.clear();
            super::bytes::merge(wire, &mut incoming, buf, ctx)?;
            if std::str::from_utf8(&incoming).is_err() {
                return Err(::prost::DecodeError::new(INVALID_UTF8));
            }
            // Validation leaves no owned FromUtf8Error on the error path.
            match String::from_utf8(incoming.take()) {
                Ok(text) => {
                    *value = text;
                    Ok(())
                }
                Err(error) => {
                    let mut bytes = Guard::new(error.into_bytes());
                    bytes.wipe();
                    Err(::prost::DecodeError::new(INVALID_UTF8))
                }
            }
        }

        pub(crate) fn merge_repeated(
            wire: WireType,
            values: &mut Vec<String>,
            buf: &mut impl ::prost::bytes::Buf,
            ctx: DecodeContext,
        ) -> Result<(), ::prost::DecodeError> {
            let mut value = Guard::new(String::new());
            merge(wire, &mut value, buf, ctx)?;
            values.push(value.take());
            Ok(())
        }
    }

    pub(crate) mod hash_map {
        use super::*;
        use crate::proto::custody::prost::MapValue;
        use crate::proto::custody::{Guard, Wipe};
        pub(crate) use ::prost::encoding::hash_map::{
            encode, encode_with_default, encoded_len, encoded_len_with_default,
        };
        use std::collections::HashMap;

        // All map keys in the vendored A2A schema are strings. Retain the callback types so prost's
        // derives infer their ordinary generic Buf parameter, while the entry uses typed dispatch.
        pub(crate) fn merge<V, B, KM, VM>(
            key_merge: KM,
            val_merge: VM,
            values: &mut HashMap<String, V>,
            buf: &mut B,
            ctx: DecodeContext,
        ) -> Result<(), ::prost::DecodeError>
        where
            V: MapValue,
            B: ::prost::bytes::Buf,
            KM: Fn(
                WireType,
                &mut String,
                &mut B,
                DecodeContext,
            ) -> Result<(), ::prost::DecodeError>,
            VM: Fn(WireType, &mut V, &mut B, DecodeContext) -> Result<(), ::prost::DecodeError>,
        {
            merge_with_default(key_merge, val_merge, V::default(), values, buf, ctx)
        }

        pub(crate) fn merge_with_default<V, B, KM, VM>(
            _key_merge: KM,
            _val_merge: VM,
            val_default: V,
            values: &mut HashMap<String, V>,
            buf: &mut B,
            ctx: DecodeContext,
        ) -> Result<(), ::prost::DecodeError>
        where
            V: MapValue,
            B: ::prost::bytes::Buf,
            KM: Fn(
                WireType,
                &mut String,
                &mut B,
                DecodeContext,
            ) -> Result<(), ::prost::DecodeError>,
            VM: Fn(WireType, &mut V, &mut B, DecodeContext) -> Result<(), ::prost::DecodeError>,
        {
            let mut entry = Entry {
                key: Guard::new(String::new()),
                value: Guard::new(val_default),
            };
            ::prost::encoding::message::merge(WireType::LengthDelimited, &mut entry, buf, ctx)?;
            if let Some(previous) = values.get_mut(&*entry.key) {
                previous.wipe();
                *previous = entry.value.take();
            } else {
                values.insert(entry.key.take(), entry.value.take());
            }
            Ok(())
        }

        /// A decode-only map entry: prost owns its length, recursion budget and unknown tags.
        pub(super) struct Entry<V: MapValue> {
            pub(super) key: Guard<String>,
            pub(super) value: Guard<V>,
        }

        impl<V: MapValue> ::prost::Message for Entry<V> {
            fn encode_raw(&self, _buf: &mut impl ::prost::bytes::BufMut) {
                unreachable!("decode-only map entry")
            }
            fn encoded_len(&self) -> usize {
                unreachable!("decode-only map entry")
            }
            fn clear(&mut self) {
                self.key.wipe();
                self.value.wipe();
                *self.key = String::new();
                *self.value = V::default();
            }
            fn merge_field(
                &mut self,
                tag: u32,
                wire: WireType,
                buf: &mut impl ::prost::bytes::Buf,
                ctx: DecodeContext,
            ) -> Result<(), ::prost::DecodeError> {
                // Protobuf map entry tags, fixed by the protobuf wire format.
                const KEY: u32 = 1;
                const VALUE: u32 = 2;
                match tag {
                    KEY => super::string::merge(wire, &mut self.key, buf, ctx),
                    VALUE => V::merge_value(wire, &mut self.value, buf, ctx),
                    _ => ::prost::encoding::skip_field(wire, tag, buf, ctx),
                }
            }
        }
    }

    pub(crate) mod btree_map {
        use std::collections::BTreeMap;

        use super::*;
        use crate::proto::custody::prost::MapValue;
        use crate::proto::custody::{Guard, Wipe};
        pub(crate) use ::prost::encoding::btree_map::{
            encode, encode_with_default, encoded_len, encoded_len_with_default,
        };

        pub(crate) fn merge<V, B, KM, VM>(
            key_merge: KM,
            val_merge: VM,
            values: &mut BTreeMap<String, V>,
            buf: &mut B,
            ctx: DecodeContext,
        ) -> Result<(), ::prost::DecodeError>
        where
            V: MapValue,
            B: ::prost::bytes::Buf,
            KM: Fn(
                WireType,
                &mut String,
                &mut B,
                DecodeContext,
            ) -> Result<(), ::prost::DecodeError>,
            VM: Fn(WireType, &mut V, &mut B, DecodeContext) -> Result<(), ::prost::DecodeError>,
        {
            merge_with_default(key_merge, val_merge, V::default(), values, buf, ctx)
        }

        pub(crate) fn merge_with_default<V, B, KM, VM>(
            _key_merge: KM,
            _val_merge: VM,
            val_default: V,
            values: &mut BTreeMap<String, V>,
            buf: &mut B,
            ctx: DecodeContext,
        ) -> Result<(), ::prost::DecodeError>
        where
            V: MapValue,
            B: ::prost::bytes::Buf,
            KM: Fn(
                WireType,
                &mut String,
                &mut B,
                DecodeContext,
            ) -> Result<(), ::prost::DecodeError>,
            VM: Fn(WireType, &mut V, &mut B, DecodeContext) -> Result<(), ::prost::DecodeError>,
        {
            let mut entry = super::hash_map::Entry {
                key: Guard::new(String::new()),
                value: Guard::new(val_default),
            };
            ::prost::encoding::message::merge(WireType::LengthDelimited, &mut entry, buf, ctx)?;
            if let Some(previous) = values.get_mut(&*entry.key) {
                previous.wipe();
                *previous = entry.value.take();
            } else {
                values.insert(entry.key.take(), entry.value.take());
            }
            Ok(())
        }
    }
}
