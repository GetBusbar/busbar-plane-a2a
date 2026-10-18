// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE FAR END'S ANSWER, SPLICED, NEVER RE-SERIALISED (Law 5: "A RELAY ... sends the client's
//! bytes with governed byte-level splices"; Q128 a2a M8). The relay reads an answer as a JSON value
//! to decide what it is (its `result` or `error`, the task's state, the far end's ids), and then
//! sends the far end's own `result` bytes on, with busbar's identity members spliced in at their
//! byte spans ([`rewrite_identity`], the byte twin of `task_identity::rewrite_identity`). Member
//! order, number spellings (an integer past 64 bits included) and every member busbar does not
//! govern reach the caller as the far end wrote them.
//!
//! A number past `f64`'s range is valid JSON that `serde_json` refuses to read; the reading copy
//! ([`readable`]) spells each such number `0` so the answer is still read, while the bytes the
//! caller receives keep the far end's spelling.

use std::borrow::Cow;
use std::ops::Range;

use serde_json::Value;

/// The nesting a scan follows before it gives up (`serde_json`'s own recursion limit).
const MAX_DEPTH: usize = 128;

/// One member of a JSON object: its decoded key and its value's span.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Member {
    key: String,
    value: Range<usize>,
}

fn ws(b: &[u8], mut i: usize) -> usize {
    while i < b.len() && matches!(b[i], b' ' | b'\t' | b'\n' | b'\r') {
        i += 1;
    }
    i
}

/// The end of the string whose opening quote is at `i`.
fn string_end(b: &[u8], i: usize) -> Option<usize> {
    let mut j = i + 1;
    while j < b.len() {
        match b[j] {
            b'"' => return Some(j + 1),
            b'\\' => j += 2,
            _ => j += 1,
        }
    }
    None
}

fn number_end(b: &[u8], i: usize) -> usize {
    let mut j = i;
    while j < b.len() && matches!(b[j], b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E') {
        j += 1;
    }
    j
}

/// The end of the JSON value starting at `i` (no leading whitespace), or `None` when it is not one.
fn value_end(b: &[u8], i: usize, depth: usize) -> Option<usize> {
    if depth > MAX_DEPTH {
        return None;
    }
    match *b.get(i)? {
        b'"' => string_end(b, i),
        b'{' => {
            let mut j = ws(b, i + 1);
            if b.get(j) == Some(&b'}') {
                return Some(j + 1);
            }
            loop {
                if b.get(j) != Some(&b'"') {
                    return None;
                }
                j = ws(b, string_end(b, j)?);
                if b.get(j) != Some(&b':') {
                    return None;
                }
                j = value_end(b, ws(b, j + 1), depth + 1)?;
                j = ws(b, j);
                match b.get(j)? {
                    b',' => j = ws(b, j + 1),
                    b'}' => return Some(j + 1),
                    _ => return None,
                }
            }
        }
        b'[' => {
            let mut j = ws(b, i + 1);
            if b.get(j) == Some(&b']') {
                return Some(j + 1);
            }
            loop {
                j = ws(b, value_end(b, j, depth + 1)?);
                match b.get(j)? {
                    b',' => j = ws(b, j + 1),
                    b']' => return Some(j + 1),
                    _ => return None,
                }
            }
        }
        b't' => b[i..].starts_with(b"true").then_some(i + 4),
        b'f' => b[i..].starts_with(b"false").then_some(i + 5),
        b'n' => b[i..].starts_with(b"null").then_some(i + 4),
        b'-' | b'0'..=b'9' => Some(number_end(b, i)),
        _ => None,
    }
}

/// The span of the one JSON value `b` holds (whitespace around it allowed), or `None`.
fn whole(b: &[u8]) -> Option<Range<usize>> {
    let start = ws(b, 0);
    let end = value_end(b, start, 0)?;
    (ws(b, end) == b.len()).then_some(start..end)
}

/// The members of the object spanning `span` (`b[span.start]` is `{`), in byte order.
fn members(b: &[u8], span: &Range<usize>) -> Option<Vec<Member>> {
    if b.get(span.start) != Some(&b'{') {
        return None;
    }
    let mut out = Vec::new();
    let mut j = ws(b, span.start + 1);
    if b.get(j) == Some(&b'}') {
        return Some(out);
    }
    loop {
        let key_end = string_end(b, j)?;
        let key: String = serde_json::from_slice(&b[j..key_end]).ok()?;
        j = ws(b, key_end);
        if b.get(j) != Some(&b':') {
            return None;
        }
        let start = ws(b, j + 1);
        let end = value_end(b, start, 1)?;
        out.push(Member {
            key,
            value: start..end,
        });
        j = ws(b, end);
        match b.get(j)? {
            b',' => j = ws(b, j + 1),
            b'}' => return Some(out),
            _ => return None,
        }
    }
}

/// The value of the LAST `key` among `members` (a duplicate reads as the last, as a parse does).
fn last<'m>(members: &'m [Member], key: &str) -> Option<&'m Member> {
    members.iter().rev().find(|m| m.key == key)
}

/// THE READING COPY of `b`: `b` itself, unless a number in it lies past `f64`'s range, which is
/// then spelled `0` (the reading never decides on a number's value; the caller's bytes keep it).
#[must_use]
pub fn readable(b: &[u8]) -> Cow<'_, [u8]> {
    let mut out: Option<Vec<u8>> = None;
    let mut i = 0;
    let mut shift = 0isize;
    while i < b.len() {
        match b[i] {
            b'"' => i = string_end(b, i).unwrap_or(b.len()),
            b'-' | b'0'..=b'9' => {
                let end = number_end(b, i);
                let past = std::str::from_utf8(&b[i..end])
                    .ok()
                    .and_then(|t| t.parse::<f64>().ok())
                    .is_some_and(f64::is_infinite);
                if past {
                    let o = out.get_or_insert_with(|| b.to_vec());
                    let at = (i as isize + shift) as usize;
                    o.splice(at..at + (end - i), *b"0");
                    shift += 1 - (end - i) as isize;
                }
                i = end;
            }
            _ => i += 1,
        }
    }
    out.map_or(Cow::Borrowed(b), Cow::Owned)
}

/// The span of `result` in the JSON-RPC envelope `envelope` (its last `result` member).
#[must_use]
pub fn result_span(envelope: &[u8]) -> Option<Range<usize>> {
    let span = whole(envelope)?;
    last(&members(envelope, &span)?, "result").map(|m| m.value.clone())
}

/// The caller's reply: `result` (the far end's bytes, spliced) under the caller's own `id`.
#[must_use]
pub fn reply(id: &Value, result: &[u8]) -> Vec<u8> {
    let id = serde_json::to_vec(id).unwrap_or_else(|_| b"null".to_vec());
    let mut out = Vec::with_capacity(result.len() + id.len() + 32);
    out.extend_from_slice(b"{\"jsonrpc\":\"2.0\",\"id\":");
    out.extend_from_slice(&id);
    out.extend_from_slice(b",\"result\":");
    out.extend_from_slice(result);
    out.push(b'}');
    out
}

/// An HTTP+JSON answer `body` re-framed as the JSON-RPC envelope answering `id`, its `result` the
/// body's own bytes (an empty body is `null`). `Err` when the body is not one JSON value.
///
/// # Errors
/// The body is not JSON.
pub fn rewrap(body: &[u8], id: &Value) -> Result<Vec<u8>, String> {
    if body.iter().all(u8::is_ascii_whitespace) {
        return Ok(reply(id, b"null"));
    }
    let span = whole(body).ok_or_else(|| "the answer is not JSON".to_string())?;
    serde_json::from_slice::<serde::de::IgnoredAny>(&readable(&body[span.clone()]))
        .map_err(|e| format!("the answer is not JSON: {e}"))?;
    Ok(reply(id, &body[span]))
}

/// The edits to one object: values replaced, and members appended before its closing brace.
#[derive(Default)]
struct Edits {
    replace: Vec<(Range<usize>, Vec<u8>)>,
}

impl Edits {
    fn set(&mut self, at: Range<usize>, bytes: Vec<u8>) {
        self.replace.push((at, bytes));
    }

    /// Set `key` of the object `obj` (its members `ms`) to `value`: every occurrence replaced, or
    /// the member appended.
    fn put(&mut self, b: &[u8], obj: &Range<usize>, ms: &[Member], key: &str, value: Vec<u8>) {
        let mut found = false;
        for m in ms.iter().filter(|m| m.key == key) {
            self.set(m.value.clone(), value.clone());
            found = true;
        }
        if !found {
            self.append(b, obj, ms.is_empty(), key, &value);
        }
    }

    fn append(&mut self, b: &[u8], obj: &Range<usize>, empty: bool, key: &str, value: &[u8]) {
        let close = obj.end - 1;
        debug_assert_eq!(b[close], b'}');
        // Several appends to one empty object: only the first goes without a comma.
        let earlier = self
            .replace
            .iter()
            .any(|(r, _)| r.start == close && r.end == close);
        let mut ins = Vec::new();
        if !empty || earlier {
            ins.push(b',');
        }
        ins.extend_from_slice(&serde_json::to_vec(key).unwrap_or_default());
        ins.push(b':');
        ins.extend_from_slice(value);
        self.set(close..close, ins);
    }

    fn apply(mut self, b: &[u8]) -> Vec<u8> {
        self.replace.sort_by_key(|(r, _)| r.start);
        let mut out = Vec::with_capacity(b.len() + 64);
        let mut at = 0;
        for (r, bytes) in self.replace {
            out.extend_from_slice(&b[at..r.start]);
            out.extend_from_slice(&bytes);
            at = r.end;
        }
        out.extend_from_slice(&b[at..]);
        out
    }
}

fn json_str(s: &str) -> Vec<u8> {
    serde_json::to_vec(s).unwrap_or_default()
}

/// A message's identity: its `taskId` and `contextId`, where it names them, are busbar's.
fn message_identity(b: &[u8], msg: &Range<usize>, task_id: &str, context_id: &str, e: &mut Edits) {
    let Some(ms) = members(b, msg) else {
        return;
    };
    for m in &ms {
        match m.key.as_str() {
            "taskId" => e.set(m.value.clone(), json_str(task_id)),
            "contextId" => e.set(m.value.clone(), json_str(context_id)),
            _ => {}
        }
    }
}

/// THE BYTE TWIN OF `task_identity::rewrite_identity`: the far end's `result` bytes with busbar's
/// task and context ids (and the matched skill) spliced in, every other byte as the far end wrote
/// it. `None` when `result` is not an object (the value path then answers).
#[must_use]
pub fn rewrite_identity(
    result: &[u8],
    wrappers: &[(&str, &str)],
    task_id: &str,
    context_id: &str,
    skill: Option<(&str, &str)>,
) -> Option<Vec<u8>> {
    let b = result;
    let top = whole(b)?;
    let top_ms = members(b, &top)?;
    let wrapped = wrappers.iter().find_map(|(w, id)| {
        last(&top_ms, w)
            .filter(|m| b[m.value.start] == b'{')
            .map(|m| (*w, *id, m.value.clone()))
    });
    let (wrapper, id_member, payload) = match wrapped {
        Some((w, id, span)) => (Some(w), id, span),
        None => (None, "id", top),
    };
    let ms = members(b, &payload)?;
    let mut e = Edits::default();
    if id_member != "taskId" || wrapper != Some("message") || last(&ms, "taskId").is_some() {
        e.put(b, &payload, &ms, id_member, json_str(task_id));
    }
    e.put(b, &payload, &ms, "contextId", json_str(context_id));
    if let Some(status) = last(&ms, "status").filter(|m| b[m.value.start] == b'{') {
        if let Some(msg) = members(b, &status.value)
            .as_deref()
            .and_then(|s| last(s, "message"))
            .filter(|m| b[m.value.start] == b'{')
        {
            message_identity(b, &msg.value, task_id, context_id, &mut e);
        }
    }
    if let Some(history) = last(&ms, "history").filter(|m| b[m.value.start] == b'[') {
        let mut j = ws(b, history.value.start + 1);
        while j < history.value.end - 1 {
            let end = value_end(b, j, 1)?;
            if b[j] == b'{' {
                message_identity(b, &(j..end), task_id, context_id, &mut e);
            }
            j = ws(b, end);
            if b.get(j) == Some(&b',') {
                j = ws(b, j + 1);
            }
        }
    }
    if let Some((key, name)) = skill {
        let entry = || {
            let mut v = b"{".to_vec();
            v.extend_from_slice(&json_str(key));
            v.push(b':');
            v.extend_from_slice(&json_str(name));
            v.push(b'}');
            v
        };
        match last(&ms, "metadata") {
            Some(meta) if b[meta.value.start] == b'{' => {
                let span = meta.value.clone();
                let meta_ms = members(b, &span)?;
                e.put(b, &span, &meta_ms, key, json_str(name));
            }
            Some(_) => {
                for m in ms.iter().filter(|m| m.key == "metadata") {
                    e.set(m.value.clone(), entry());
                }
            }
            None => e.append(b, &payload, ms.is_empty(), "metadata", &entry()),
        }
    }
    Some(e.apply(b))
}

#[cfg(test)]
#[path = "tests/answer_bytes_tests.rs"]
mod tests;
