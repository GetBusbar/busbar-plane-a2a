// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Scoped owners for generated protobuf and ProtoJSON values, including unfinished visitors.

use std::collections::{BTreeMap, HashMap};
use std::hash::Hash;
use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};

use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use zeroize::Zeroize;

#[path = "proto_custody_prost.rs"]
#[allow(dead_code, unused_imports)]
// Preserve prost's generated helper surface in the local facade.
pub(crate) mod prost;

/// Wipe only initialized values. Containers drain keys as well as recursively owned values.
pub(crate) trait Wipe {
    fn wipe(&mut self);
}

macro_rules! inert {
    ($($ty:ty),* $(,)?) => { $(impl Wipe for $ty { fn wipe(&mut self) {} })* };
}
inert!(bool, i32, i64, u32, u64, f32, f64);

impl Wipe for u8 {
    fn wipe(&mut self) {
        self.zeroize();
    }
}

impl Wipe for String {
    fn wipe(&mut self) {
        self.zeroize();
    }
}

impl<T: Wipe> Wipe for Option<T> {
    fn wipe(&mut self) {
        if let Some(value) = self {
            value.wipe();
        }
    }
}

impl<T: Wipe> Wipe for Box<T> {
    fn wipe(&mut self) {
        (**self).wipe();
    }
}

impl<T: Wipe> Wipe for Vec<T> {
    fn wipe(&mut self) {
        self.iter_mut().for_each(Wipe::wipe);
    }
}

impl<K: Wipe + Eq + Hash, V: Wipe> Wipe for HashMap<K, V> {
    fn wipe(&mut self) {
        for (mut key, mut value) in self.drain() {
            key.wipe();
            value.wipe();
        }
    }
}

impl<K: Wipe + Ord, V: Wipe> Wipe for BTreeMap<K, V> {
    fn wipe(&mut self) {
        for (mut key, mut value) in std::mem::take(self) {
            key.wipe();
            value.wipe();
        }
    }
}

/// A partial field, collection or pending map key retains custody until transfer.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Guard<T: Wipe>(T);

impl<T: Wipe> std::fmt::Debug for Guard<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Guard([REDACTED])")
    }
}

impl<A: Wipe, B: Wipe> Wipe for (A, B) {
    fn wipe(&mut self) {
        self.0.wipe();
        self.1.wipe();
    }
}

impl<T: Wipe> Guard<T> {
    pub(crate) fn new(value: T) -> Self {
        Self(value)
    }
    pub(crate) fn take(&mut self) -> T
    where
        T: Default,
    {
        std::mem::take(&mut self.0)
    }
}

impl<T: Wipe> Deref for Guard<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T: Wipe> DerefMut for Guard<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T: Wipe> Drop for Guard<T> {
    fn drop(&mut self) {
        self.0.wipe();
    }
}

impl<T: Wipe + serde::Serialize> serde::Serialize for Guard<T> {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(ser)
    }
}

pub(crate) fn encode_base64(value: impl AsRef<[u8]>) -> Guard<String> {
    use base64::Engine as _;
    Guard::new(base64::engine::general_purpose::STANDARD.encode(value))
}

/// Build test messages without moving unnamed fields out of a Drop-bearing default value.
#[cfg(test)]
pub(crate) fn initialized<T: Wipe + Default>(initialize: impl FnOnce(&mut T)) -> T {
    let mut value = Guard::new(T::default());
    initialize(&mut value);
    value.take()
}

/// Deserialize collections through their own guards rather than Serde's plain partial locals.
pub(crate) trait Decode<'de>: Sized + Wipe {
    fn decode<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error>;
}

pub(crate) struct Seed<T>(PhantomData<T>);

impl<T> Seed<T> {
    pub(crate) fn new() -> Self {
        Self(PhantomData)
    }
}

impl<'de, T: Decode<'de>> DeserializeSeed<'de> for Seed<T> {
    type Value = T;
    fn deserialize<D: Deserializer<'de>>(self, de: D) -> Result<T, D::Error> {
        T::decode(de)
    }
}

macro_rules! native {
    ($($ty:ty),* $(,)?) => { $(impl<'de> Decode<'de> for $ty {
        fn decode<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
            Deserialize::deserialize(de)
        }
    })* };
}
native!(String, bool, u8, i32, i64, u32, u64, f32, f64);

impl<'de, T: Decode<'de>> Decode<'de> for Option<T> {
    fn decode<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        struct Optional<T>(PhantomData<T>);
        impl<'de, T: Decode<'de>> Visitor<'de> for Optional<T> {
            type Value = Option<T>;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("an optional protobuf field")
            }
            fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(None)
            }
            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(None)
            }
            fn visit_some<D: Deserializer<'de>>(self, de: D) -> Result<Self::Value, D::Error> {
                T::decode(de).map(Some)
            }
        }
        de.deserialize_option(Optional(PhantomData))
    }
}

impl<'de, T: Decode<'de>> Decode<'de> for Box<T> {
    fn decode<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        T::decode(de).map(Box::new)
    }
}

impl<'de, T: Decode<'de>> Decode<'de> for Vec<T> {
    fn decode<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        struct Sequence<T>(PhantomData<T>);
        impl<'de, T: Decode<'de>> Visitor<'de> for Sequence<T> {
            type Value = Vec<T>;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a sequence")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut values = Guard::new(Vec::new());
                while let Some(value) = seq.next_element_seed(Seed::<T>::new())? {
                    values.push(value);
                }
                Ok(values.take())
            }
        }
        de.deserialize_seq(Sequence(PhantomData))
    }
}

impl<'de, K, V> Decode<'de> for HashMap<K, V>
where
    K: Decode<'de> + Eq + Hash + Default,
    V: Decode<'de>,
{
    fn decode<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        struct Object<K, V>(PhantomData<(K, V)>);
        impl<'de, K, V> Visitor<'de> for Object<K, V>
        where
            K: Decode<'de> + Eq + Hash + Default,
            V: Decode<'de>,
        {
            type Value = HashMap<K, V>;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a map")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut fields = Guard::new(HashMap::<K, V>::new());
                while let Some(key) = map.next_key_seed(Seed::<K>::new())? {
                    let mut key = Guard::new(key);
                    let value = map.next_value_seed(Seed::<V>::new())?;
                    if let Some(previous) = fields.get_mut(&*key) {
                        previous.wipe();
                        *previous = value;
                    } else {
                        fields.insert(key.take(), value);
                    }
                    // An equal incoming key stays under its guard; the existing key is retained.
                }
                Ok(fields.take())
            }
        }
        de.deserialize_map(Object(PhantomData))
    }
}

/// pbjson's numeric compatibility (number or string), without an owned untagged Content local.
pub(crate) struct NumberDeserialize<T>(pub(crate) T);

impl<T: Wipe> Wipe for NumberDeserialize<T> {
    fn wipe(&mut self) {
        self.0.wipe();
    }
}

impl<'de, T> Decode<'de> for NumberDeserialize<T>
where
    T: Wipe + std::str::FromStr + Deserialize<'de>,
    T::Err: std::error::Error,
{
    fn decode<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        struct Number<T>(PhantomData<T>);
        impl<'de, T> Visitor<'de> for Number<T>
        where
            T: std::str::FromStr + Deserialize<'de>,
            T::Err: std::error::Error,
        {
            type Value = T;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a number or a numeric string")
            }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<T, E> {
                value.parse().map_err(de::Error::custom)
            }
            fn visit_string<E: de::Error>(self, value: String) -> Result<T, E> {
                self.visit_str(&Guard::new(value))
            }
            fn visit_i64<E: de::Error>(self, value: i64) -> Result<T, E> {
                T::deserialize(serde::de::value::I64Deserializer::new(value))
            }
            fn visit_u64<E: de::Error>(self, value: u64) -> Result<T, E> {
                T::deserialize(serde::de::value::U64Deserializer::new(value))
            }
            fn visit_f64<E: de::Error>(self, value: f64) -> Result<T, E> {
                T::deserialize(serde::de::value::F64Deserializer::new(value))
            }
        }
        de.deserialize_any(Number(PhantomData)).map(Self)
    }
}

/// pbjson's bytes compatibility, with fully initialized guarded output on both decode attempts.
pub(crate) struct BytesDeserialize<T>(pub(crate) T);

impl<T: Wipe> Wipe for BytesDeserialize<T> {
    fn wipe(&mut self) {
        self.0.wipe();
    }
}

impl<'de> Decode<'de> for BytesDeserialize<Vec<u8>> {
    fn decode<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        struct Bytes;
        impl Visitor<'_> for Bytes {
            type Value = Vec<u8>;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a base64 string")
            }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<Vec<u8>, E> {
                use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
                use base64::Engine as _;
                const PADDING: GeneralPurposeConfig = GeneralPurposeConfig::new()
                    .with_decode_padding_mode(DecodePaddingMode::Indifferent);
                const STANDARD: GeneralPurpose =
                    GeneralPurpose::new(&base64::alphabet::STANDARD, PADDING);
                const URL_SAFE: GeneralPurpose =
                    GeneralPurpose::new(&base64::alphabet::URL_SAFE, PADDING);
                let mut bytes =
                    zeroize::Zeroizing::new(vec![0; base64::decoded_len_estimate(value.len())]);
                let decoded = STANDARD
                    .decode_slice(value, &mut bytes)
                    .or_else(|error| match error {
                        base64::DecodeSliceError::DecodeError(
                            base64::DecodeError::InvalidByte(_, b'-' | b'_'),
                        ) => {
                            bytes.as_mut_slice().zeroize();
                            URL_SAFE.decode_slice(value, &mut bytes)
                        }
                        _ => Err(error),
                    })
                    .map_err(de::Error::custom)?;
                // decode_slice may initialize bytes beyond its result on an error; the entire
                // destination was already initialized and stays under Zeroizing until transfer.
                bytes[decoded..].zeroize();
                bytes.truncate(decoded);
                Ok(std::mem::take(&mut *bytes))
            }
            fn visit_string<E: de::Error>(self, value: String) -> Result<Vec<u8>, E> {
                self.visit_str(&Guard::new(value))
            }
        }
        de.deserialize_str(Bytes).map(Self)
    }
}
