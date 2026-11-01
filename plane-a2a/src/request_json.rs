// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Owned request JSON can contain a callback credential anywhere in its extensions.

use std::ops::{Deref, DerefMut};

use serde_json::Value;
use zeroize::Zeroize;

use crate::proto::custody::{Decode, Guard, Seed, Wipe};

/// A parsed request and every clone of it wipe their strings when their owner ends.
#[derive(Clone, Default, serde::Serialize)]
#[serde(transparent)]
pub(crate) struct RequestJson(Value);

impl Wipe for Value {
    fn wipe(&mut self) {
        wipe(self);
    }
}

impl<'de> Decode<'de> for Value {
    fn decode<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        use serde::Deserialize as _;
        RequestJson::deserialize(de).map(RequestJson::into_value)
    }
}

impl<'de> serde::Deserialize<'de> for RequestJson {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        use serde::de::{self, MapAccess, SeqAccess, Visitor};
        struct Document;
        impl<'de> Visitor<'de> for Document {
            type Value = RequestJson;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("any valid JSON value")
            }
            fn visit_bool<E: de::Error>(self, value: bool) -> Result<Self::Value, E> {
                Ok(RequestJson(Value::Bool(value)))
            }
            fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
                Ok(RequestJson(Value::Number(value.into())))
            }
            fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
                Ok(RequestJson(Value::Number(value.into())))
            }
            fn visit_i128<E: de::Error>(self, value: i128) -> Result<Self::Value, E> {
                let de = serde::de::value::I128Deserializer::new(value);
                serde::Deserialize::deserialize(de)
                    .map(Value::Number)
                    .map(RequestJson)
            }
            fn visit_u128<E: de::Error>(self, value: u128) -> Result<Self::Value, E> {
                let de = serde::de::value::U128Deserializer::new(value);
                serde::Deserialize::deserialize(de)
                    .map(Value::Number)
                    .map(RequestJson)
            }
            fn visit_f64<E: de::Error>(self, value: f64) -> Result<Self::Value, E> {
                Ok(RequestJson(
                    serde_json::Number::from_f64(value).map_or(Value::Null, Value::Number),
                ))
            }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(RequestJson(Value::String(value.to_owned())))
            }
            fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
                Ok(RequestJson(Value::String(value)))
            }
            fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(RequestJson::default())
            }
            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(RequestJson::default())
            }
            fn visit_some<D: serde::Deserializer<'de>>(
                self,
                de: D,
            ) -> Result<Self::Value, D::Error> {
                serde::Deserialize::deserialize(de)
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut values = Guard::new(Vec::new());
                while let Some(value) = seq.next_element_seed(Seed::<Value>::new())? {
                    values.push(value);
                }
                Ok(RequestJson(Value::Array(values.take())))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut document = RequestJson(Value::Object(serde_json::Map::new()));
                let values = document.as_object_mut().expect("object constructed above");
                while let Some(key) = map.next_key_seed(Seed::<String>::new())? {
                    let mut key = Guard::new(key);
                    let value = map.next_value_seed(Seed::<Value>::new())?;
                    if let Some(previous) = values.get_mut(&*key) {
                        previous.wipe();
                        *previous = value;
                    } else {
                        values.insert(key.take(), value);
                    }
                }
                Ok(document)
            }
        }
        de.deserialize_any(Document)
    }
}

impl RequestJson {
    pub(crate) fn new(value: Value) -> Self {
        Self(value)
    }

    /// Transfer into another guarded owner or the SDK invocation's final owner.
    pub(crate) fn into_value(mut self) -> Value {
        std::mem::take(&mut self.0)
    }
}

/// An arrival's optional request, including the local/refused path that keeps no hop.
pub(crate) struct OptionalRequest(Option<Value>);

impl OptionalRequest {
    pub(crate) fn new(value: Option<Value>) -> Self {
        Self(value)
    }
}

impl Deref for OptionalRequest {
    type Target = Option<Value>;
    fn deref(&self) -> &Option<Value> {
        &self.0
    }
}

impl DerefMut for OptionalRequest {
    fn deref_mut(&mut self) -> &mut Option<Value> {
        &mut self.0
    }
}

impl Drop for OptionalRequest {
    fn drop(&mut self) {
        if let Some(value) = &mut self.0 {
            wipe(value);
        }
    }
}

impl std::fmt::Debug for RequestJson {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RequestJson([REDACTED])")
    }
}

impl Deref for RequestJson {
    type Target = Value;
    fn deref(&self) -> &Value {
        &self.0
    }
}

impl DerefMut for RequestJson {
    fn deref_mut(&mut self) -> &mut Value {
        &mut self.0
    }
}

fn wipe_string(value: &mut String) {
    #[cfg(test)]
    crate::tests::request_custody_probe::observe(false, value);
    // Keep the initialized prefix live for the safe witness, then wipe its allocation too.
    value.as_mut_str().zeroize();
    #[cfg(test)]
    crate::tests::request_custody_probe::observe(true, value);
    value.zeroize();
}

fn wipe(value: &mut Value) {
    match value {
        Value::String(text) => wipe_string(text),
        Value::Array(values) => values.iter_mut().for_each(wipe),
        Value::Object(values) => {
            for (mut key, mut value) in std::mem::take(values) {
                wipe_string(&mut key);
                wipe(&mut value);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

impl Drop for RequestJson {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::RequestJson;

    #[test]
    fn malformed_later_array_item_wipes_the_initialized_prior_value() {
        crate::tests::request_custody_probe::assert_wiped(|| {
            let input = br#"["callback-credential-custody-canary",{"unfinished":]"#;
            assert!(serde_json::from_slice::<RequestJson>(input).is_err());
        });
    }

    #[test]
    fn duplicate_object_member_wipes_its_superseded_value() {
        crate::tests::request_custody_probe::assert_wiped(|| {
            let input = br#"{"credential":"callback-credential-custody-canary","credential":"replacement"}"#;
            let document: RequestJson = serde_json::from_slice(input).unwrap();
            assert_eq!(document["credential"], "replacement");
        });
    }
}
