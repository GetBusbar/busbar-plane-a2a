// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Custody regressions over the same generated messages and WKT source the framed codec uses.

use prost::encoding::{encode_key, encode_varint, WireType};
use prost::Message;
use serde::de::value::{Error, MapDeserializer, SeqDeserializer};
use serde::de::{IntoDeserializer, Visitor};
use serde::{Deserialize, Deserializer};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

#[allow(dead_code, unused_imports)]
#[path = "../src/proto_custody.rs"]
pub(crate) mod custody_impl;

mod proto {
    pub(crate) use crate::custody_impl as custody;
}
#[allow(dead_code)]
#[path = "../src/wkt.rs"]
mod wkt;

#[allow(dead_code, clippy::all, clippy::pedantic)]
mod pb {
    include!(concat!(env!("OUT_DIR"), "/lf.a2a.v1.rs"));
    include!(concat!(env!("OUT_DIR"), "/lf.a2a.v1.serde.rs"));
}
thread_local! {
    static WATCH: Cell<Option<(*mut u8, usize)>> = const { Cell::new(None) };
    static WIPED: Cell<Option<bool>> = const { Cell::new(None) };
}

struct InspectBeforeFree;

// SAFETY: allocations are forwarded unchanged to System. Only the initialized string prefix
// registered by this thread is observed, while its matching allocation still belongs to it.
unsafe impl GlobalAlloc for InspectBeforeFree {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the allocator caller supplies a valid layout.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        let _ = WATCH.try_with(|watch| {
            if let Some((watched, len)) = watch.get().filter(|(watched, _)| *watched == pointer) {
                watch.set(None);
                let wiped = len <= layout.size()
                    && (0..len).all(|index| {
                        // SAFETY: these bytes were initialized String contents when registered,
                        // and the matching live allocation has not yet reached System.dealloc.
                        // No spare capacity, allocation padding, or freed memory is read.
                        unsafe { pointer.add(index).read_volatile() == 0 }
                    });
                let _ = WIPED.try_with(|result| result.set(Some(wiped)));
            }
        });
        // SAFETY: pointer and layout match the allocator caller's live allocation.
        unsafe { System.dealloc(pointer, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: InspectBeforeFree = InspectBeforeFree;

fn watch(bytes: &[u8]) {
    assert!(!bytes.is_empty());
    WATCH.with(|watched| watched.set(Some((bytes.as_ptr().cast_mut(), bytes.len()))));
    WIPED.with(|result| result.set(None));
}

#[test]
fn initialized_prefix_witness_distinguishes_cleartext_and_wiped_owners() {
    let plain = "typed-private-control".to_string();
    watch(plain.as_bytes());
    drop(plain);
    assert_eq!(WIPED.with(Cell::get), Some(false));
    let wiped = zeroize::Zeroizing::new("typed-private-control".to_string());
    watch(wiped.as_bytes());
    drop(wiped);
    assert_eq!(WIPED.with(Cell::get), Some(true));
}

#[test]
fn generated_authentication_owner_wipes_after_successful_protojson_render() {
    let message = pb::AuthenticationInfo {
        scheme: "Bearer".into(),
        credentials: "typed-private-credential".into(),
    };
    let rendered = serde_json::to_value(&message).unwrap();
    assert_eq!(rendered["credentials"], "typed-private-credential");
    watch(message.credentials.as_bytes());
    drop(message);
    assert_eq!(WIPED.with(Cell::get), Some(true));
}

#[test]
fn generated_pbjson_partial_field_wipes_when_a_later_field_is_duplicated() {
    let credential = "typed-private-credential".to_string();
    watch(credential.as_bytes());
    let input = MapDeserializer::<_, Error>::new(
        [
            ("credentials", credential),
            ("credentials", "duplicate".to_string()),
        ]
        .into_iter(),
    );
    let result = pb::AuthenticationInfo::deserialize(input);
    assert!(result.is_err());
    assert_eq!(WIPED.with(Cell::get), Some(true));
}

#[test]
fn prost_merge_wipes_replaced_credential_before_reallocation() {
    let mut message = pb::AuthenticationInfo {
        scheme: "Bearer".into(),
        credentials: "old-private-credential".into(),
    };
    let replacement = "new-private-credential".repeat(message.credentials.capacity() + 1);
    let bytes = pb::AuthenticationInfo {
        scheme: "Bearer".into(),
        credentials: replacement.clone(),
    }
    .encode_to_vec();
    watch(message.credentials.as_bytes());
    message.merge(bytes.as_slice()).unwrap();
    assert_eq!(message.credentials, replacement);
    assert_eq!(WIPED.with(Cell::get), Some(true));
}

#[test]
fn prost_merge_error_wipes_credential_even_after_invalid_utf8_clears_length() {
    let mut message = pb::AuthenticationInfo {
        scheme: "Bearer".into(),
        credentials: "old-private-credential".into(),
    };
    watch(message.credentials.as_bytes());

    const AUTHENTICATION_CREDENTIALS_FIELD: u32 = 2;
    const INVALID_UTF8_LEADING_BYTE: u8 = 0xff;
    let payload = [INVALID_UTF8_LEADING_BYTE];
    let mut bytes = Vec::new();
    encode_key(
        AUTHENTICATION_CREDENTIALS_FIELD,
        WireType::LengthDelimited,
        &mut bytes,
    );
    encode_varint(payload.len() as u64, &mut bytes);
    bytes.extend_from_slice(&payload);
    assert!(message.merge(bytes.as_slice()).is_err());
    drop(message);
    assert_eq!(WIPED.with(Cell::get), Some(true));
}

enum Element {
    Text(String),
    Fail,
}
impl<'de> IntoDeserializer<'de, Error> for Element {
    type Deserializer = Self;
    fn into_deserializer(self) -> Self {
        self
    }
}
impl<'de> Deserializer<'de> for Element {
    type Error = Error;
    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        match self {
            Self::Text(text) => visitor.visit_string(text),
            Self::Fail => Err(serde::de::Error::custom("later element failed")),
        }
    }
    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        visitor.visit_some(self)
    }
    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 u8 u16 u32 u64 f32 f64 char str string bytes byte_buf
        unit unit_struct newtype_struct seq tuple tuple_struct map struct enum identifier ignored_any
    }
}

#[test]
fn wkt_partial_list_wipes_prior_values_when_a_later_element_fails() {
    let credential = "wkt-private-credential".to_string();
    watch(credential.as_bytes());
    let input =
        SeqDeserializer::<_, Error>::new([Element::Text(credential), Element::Fail].into_iter());
    assert!(wkt::ListValue::deserialize(input).is_err());
    assert_eq!(WIPED.with(Cell::get), Some(true));
}

#[test]
fn generated_repeated_string_wipes_prior_elements_when_a_later_element_fails() {
    let credential = "repeated-private-credential".to_string();
    watch(credential.as_bytes());
    let values =
        SeqDeserializer::<_, Error>::new([Element::Text(credential), Element::Fail].into_iter());
    let input = MapDeserializer::<_, Error>::new([("list", values)].into_iter());
    assert!(pb::StringList::deserialize(input).is_err());
    assert_eq!(WIPED.with(Cell::get), Some(true));
}

#[test]
fn generated_map_wipes_a_pending_key_when_its_value_fails() {
    let key = "scope-private-credential".to_string();
    watch(key.as_bytes());
    let scopes = MapDeserializer::<_, Error>::new([(key, Element::Fail)].into_iter());
    let input = MapDeserializer::<_, Error>::new([("scopes", scopes)].into_iter());
    assert!(pb::ClientCredentialsOAuthFlow::deserialize(input).is_err());
    assert_eq!(WIPED.with(Cell::get), Some(true));
}

#[test]
fn wkt_map_wipes_a_pending_key_when_its_value_fails() {
    let key = "key-private-credential".to_string();
    watch(key.as_bytes());
    let input = MapDeserializer::<_, Error>::new([(key, Element::Fail)].into_iter());
    assert!(wkt::Struct::deserialize(input).is_err());
    assert_eq!(WIPED.with(Cell::get), Some(true));
}

#[test]
fn wkt_map_wipes_the_discarded_equal_incoming_key() {
    let key = "key-private-credential".to_string();
    let duplicate = key.clone();
    watch(duplicate.as_bytes());
    let input = MapDeserializer::<_, Error>::new(
        [
            (key, Element::Text("earlier".to_owned())),
            (duplicate, Element::Text("replacement".to_owned())),
        ]
        .into_iter(),
    );
    let value = wkt::Struct::deserialize(input).unwrap();
    assert_eq!(WIPED.with(Cell::get), Some(true));
    assert_eq!(value.fields.len(), 1);
}
