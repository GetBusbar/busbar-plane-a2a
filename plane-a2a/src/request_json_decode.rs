// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Decode strings directly into guarded, preallocated owners after a non-copying grammar pass.

use serde_json::Value;

use super::RequestJson;
use crate::proto::custody::Guard;

pub(super) fn parse(
    bytes: &[u8],
    allow_duplicates: bool,
) -> Result<RequestJson, serde_json::Error> {
    serde_json::from_slice::<serde::de::IgnoredAny>(bytes)?;
    let mut cursor = Cursor {
        bytes,
        at: 0,
        allow_duplicates,
        retain: true,
    };
    let value = cursor
        .value(0)
        .ok_or_else(|| <serde_json::Error as serde::de::Error>::custom("invalid JSON value"))?;
    cursor.whitespace();
    if cursor.at != bytes.len() {
        return Err(<serde_json::Error as serde::de::Error>::custom(
            "trailing JSON value",
        ));
    }
    Ok(value)
}

pub(super) fn validate(bytes: &[u8]) -> bool {
    if serde_json::from_slice::<serde::de::IgnoredAny>(bytes).is_err() {
        return false;
    }
    let mut cursor = Cursor {
        bytes,
        at: 0,
        allow_duplicates: true,
        retain: false,
    };
    cursor.value(0).is_some()
}

struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
    allow_duplicates: bool,
    retain: bool,
}

impl Cursor<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }

    fn whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\r' | b'\n')) {
            self.at += 1;
        }
    }

    fn eat(&mut self, byte: u8) -> bool {
        if self.peek() != Some(byte) {
            return false;
        }
        self.at += 1;
        true
    }

    fn value(&mut self, depth: usize) -> Option<RequestJson> {
        if depth >= 128 {
            return None;
        }
        self.whitespace();
        match self.peek()? {
            b'"' => {
                let mut string = self.string()?;
                Some(RequestJson::new(if self.retain {
                    Value::String(string.take())
                } else {
                    Value::Null
                }))
            }
            b'[' => {
                self.at += 1;
                let mut values = Guard::new(Vec::<Value>::new());
                self.whitespace();
                if !self.eat(b']') {
                    loop {
                        let value = self.value(depth + 1)?;
                        if self.retain {
                            values.push(value.into_value());
                        }
                        self.whitespace();
                        if self.eat(b']') {
                            break;
                        }
                        if !self.eat(b',') {
                            return None;
                        }
                    }
                }
                Some(RequestJson::new(Value::Array(values.take())))
            }
            b'{' => {
                self.at += 1;
                let mut document = RequestJson::new(Value::Object(serde_json::Map::new()));
                self.whitespace();
                if !self.eat(b'}') {
                    loop {
                        self.whitespace();
                        let mut key = self.string()?;
                        self.whitespace();
                        if !self.eat(b':') {
                            return None;
                        }
                        let value = self.value(depth + 1)?;
                        if self.retain {
                            let map = document.as_object_mut()?;
                            if let Some(previous) = map.get_mut(&*key) {
                                if !self.allow_duplicates {
                                    return None;
                                }
                                super::wipe(previous);
                                *previous = value.into_value();
                            } else {
                                map.insert(key.take(), value.into_value());
                            }
                        }
                        self.whitespace();
                        if self.eat(b'}') {
                            break;
                        }
                        if !self.eat(b',') {
                            return None;
                        }
                    }
                }
                Some(document)
            }
            _ => {
                let start = self.at;
                while !matches!(
                    self.peek(),
                    None | Some(b' ' | b'\t' | b'\r' | b'\n' | b',' | b']' | b'}')
                ) {
                    self.at += 1;
                }
                let raw = self.bytes.get(start..self.at)?;
                let value = match raw {
                    b"null" => Value::Null,
                    b"true" => Value::Bool(true),
                    b"false" => Value::Bool(false),
                    _ => Value::Number(serde_json::from_slice(raw).ok()?),
                };
                Some(RequestJson::new(value))
            }
        }
    }

    fn string(&mut self) -> Option<Guard<String>> {
        if !self.eat(b'"') {
            return None;
        }
        let start = self.at;
        loop {
            match self.peek()? {
                b'"' => {
                    let raw = self.bytes.get(start..self.at)?;
                    self.at += 1;
                    return unescape(raw);
                }
                b'\\' => self.at += 2,
                _ => self.at += 1,
            }
        }
    }
}

/// Escapes never expand beyond their encoded width; this allocation never reallocates.
fn unescape(raw: &[u8]) -> Option<Guard<String>> {
    let mut out = Guard::new(String::with_capacity(raw.len()));
    let mut at = 0;
    loop {
        let start = at;
        while raw.get(at).is_some_and(|byte| *byte != b'\\') {
            at += 1;
        }
        out.push_str(std::str::from_utf8(raw.get(start..at)?).ok()?);
        if at == raw.len() {
            return Some(out);
        }
        let escaped = *raw.get(at + 1)?;
        at += 2;
        let character = match escaped {
            b'"' => '"',
            b'\\' => '\\',
            b'/' => '/',
            b'b' => '\u{8}',
            b'f' => '\u{c}',
            b'n' => '\n',
            b'r' => '\r',
            b't' => '\t',
            b'u' => {
                let high = hex4(raw.get(at..at + 4)?)?;
                at += 4;
                if (0xD800..0xDC00).contains(&high) {
                    if raw.get(at..at + 2)? != b"\\u" {
                        return None;
                    }
                    let low = hex4(raw.get(at + 2..at + 6)?)?;
                    at += 6;
                    if !(0xDC00..0xE000).contains(&low) {
                        return None;
                    }
                    char::from_u32(0x10000 + ((high - 0xD800) << 10) + low - 0xDC00)?
                } else {
                    char::from_u32(high)?
                }
            }
            _ => return None,
        };
        out.push(character);
    }
}

fn hex4(bytes: &[u8]) -> Option<u32> {
    bytes.iter().try_fold(0u32, |value, byte| {
        Some(value * 16 + char::from(*byte).to_digit(16)?)
    })
}
