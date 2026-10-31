// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The far end's answer, spliced, never re-serialised (a relay sends the client's bytes with
//! governed byte-level splices). The relay reads off an answer's bytes
//! what it is (its `result` or `error`; the task's state and the far end's ids from its `result`
//! alone, as a value), and then
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

use busbar_contract::spans::{resolve_pointer, Resolved};
use serde_json::Value;

/// One member of a JSON object: its decoded key and its value's span.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ObjectMember {
    key: String,
    value: Range<usize>,
}

/// `i` moved past the JSON whitespace at it.
fn past_blank(b: &[u8], mut i: usize) -> usize {
    while i < b.len() && matches!(b[i], b' ' | b'\t' | b'\n' | b'\r') {
        i += 1;
    }
    i
}

/// The span of the JSON value at `i` (whitespace before it allowed), read by the contract's one
/// span grammar (`busbar_contract::spans`), never a plane-local copy of it. A number that runs to
/// the end of `b` ends there: the grammar answers `NeedMore` for it, as a later chunk could add
/// digits, and the bytes here are the whole answer.
fn value_at(b: &[u8], i: usize) -> Option<Range<usize>> {
    let rest = b.get(i..)?;
    match resolve_pointer(rest, "") {
        Resolved::Found(span) => Some(i + span.start..i + span.end),
        Resolved::NeedMore => {
            let at = past_blank(b, i);
            let digits = b.get(at..)?;
            let number = matches!(digits.first(), Some(b'-' | b'0'..=b'9'))
                && digits
                    .iter()
                    .all(|c| matches!(c, b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E'));
            number.then_some(at..b.len())
        }
        Resolved::Missing | Resolved::Malformed => None,
    }
}

/// The span of the one JSON value `b` holds (whitespace around it allowed), or `None`.
fn document(b: &[u8]) -> Option<Range<usize>> {
    let span = value_at(b, 0)?;
    (past_blank(b, span.end) == b.len()).then_some(span)
}

/// The members of the object spanning `span` (`b[span.start]` is `{`), in byte order.
fn object_members(b: &[u8], span: &Range<usize>) -> Option<Vec<ObjectMember>> {
    if b.get(span.start) != Some(&b'{') {
        return None;
    }
    let mut out = Vec::new();
    let mut j = past_blank(b, span.start + 1);
    if b.get(j) == Some(&b'}') {
        return Some(out);
    }
    loop {
        if b.get(j) != Some(&b'"') {
            return None;
        }
        let key_span = value_at(b, j)?;
        let key: String = serde_json::from_slice(&b[key_span.clone()]).ok()?;
        j = past_blank(b, key_span.end);
        if b.get(j) != Some(&b':') {
            return None;
        }
        let value = value_at(b, j + 1)?;
        j = past_blank(b, value.end);
        out.push(ObjectMember { key, value });
        match b.get(j)? {
            b',' => j = past_blank(b, j + 1),
            b'}' => return Some(out),
            _ => return None,
        }
    }
}

/// The value of the LAST `key` among `members` (a duplicate reads as the last, as a parse does).
fn last<'m>(members: &'m [ObjectMember], key: &str) -> Option<&'m ObjectMember> {
    members.iter().rev().find(|m| m.key == key)
}

/// THE READING COPY of `b`: `b` itself, unless a number in it lies past `f64`'s range, which is
/// then spelled `0` (the reading never decides on a number's value; the caller's bytes keep it).
#[must_use]
pub fn readable(b: &[u8]) -> Cow<'_, [u8]> {
    // Built in ONE pass: the run since the last replacement, then `0` (a far end's answer is
    // untrusted, so no per-number shift of the whole tail).
    let mut out: Option<Vec<u8>> = None;
    let mut copied = 0;
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'"' => i = value_at(b, i).map_or(b.len(), |v| v.end),
            b'-' | b'0'..=b'9' => {
                let end = value_at(b, i).map_or(i + 1, |v| v.end);
                let past = std::str::from_utf8(&b[i..end])
                    .ok()
                    .and_then(|t| t.parse::<f64>().ok())
                    .is_some_and(f64::is_infinite);
                if past {
                    let o = out.get_or_insert_with(|| Vec::with_capacity(b.len()));
                    o.extend_from_slice(&b[copied..i]);
                    o.push(b'0');
                    copied = end;
                }
                i = end;
            }
            _ => i += 1,
        }
    }
    out.map_or(Cow::Borrowed(b), |mut o| {
        o.extend_from_slice(&b[copied..]);
        Cow::Owned(o)
    })
}

/// The span of `result` in the JSON-RPC envelope `envelope` (its last `result` member).
#[must_use]
pub fn result_span(envelope: &[u8]) -> Option<Range<usize>> {
    member_span(envelope, "result")
}

/// The span of the object `doc`'s last `key` member.
#[must_use]
pub fn member_span(doc: &[u8], key: &str) -> Option<Range<usize>> {
    let span = document(doc)?;
    last(&object_members(doc, &span)?, key).map(|m| m.value.clone())
}

/// WHETHER `b` IS THE JSON A PARSE TO A VALUE READS (every token, every string, the parse's depth
/// bound), read through and dropped: no value is built.
#[must_use]
pub fn is_json(b: &[u8]) -> bool {
    serde_json::from_slice::<Shape>(b).is_ok()
}

/// A JSON value read and dropped, at every level as a value's parse reads it.
struct Shape;

impl<'de> serde::Deserialize<'de> for Shape {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(Shape)
    }
}

impl<'de> serde::de::Visitor<'de> for Shape {
    type Value = Shape;
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a JSON value")
    }
    fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<Shape, E> {
        Ok(Shape)
    }
    fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<Shape, E> {
        Ok(Shape)
    }
    fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<Shape, E> {
        Ok(Shape)
    }
    fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<Shape, E> {
        Ok(Shape)
    }
    fn visit_str<E: serde::de::Error>(self, _: &str) -> Result<Shape, E> {
        Ok(Shape)
    }
    fn visit_unit<E: serde::de::Error>(self) -> Result<Shape, E> {
        Ok(Shape)
    }
    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut s: A) -> Result<Shape, A::Error> {
        while s.next_element::<Shape>()?.is_some() {}
        Ok(Shape)
    }
    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut m: A) -> Result<Shape, A::Error> {
        while m.next_entry::<Shape, Shape>()?.is_some() {}
        Ok(Shape)
    }
}

/// THE JSON-RPC ANSWER `envelope` AS THE CONTRACT'S READER JUDGES IT, read off its bytes: its
/// `jsonrpc` and `id` as values (through the reading copy), its `error` as present (`null` kept
/// `null`) and its `result` as present, and the span of its `result`. Nothing else is read into a
/// value. `None` when `envelope` is no JSON object.
#[must_use]
pub fn envelope_reading(envelope: &[u8]) -> Option<(Value, Option<Range<usize>>)> {
    let members = object_members(envelope, &document(envelope)?)?;
    let mut judged = serde_json::Map::new();
    for key in ["jsonrpc", "id"] {
        if let Some(m) = last(&members, key) {
            let value = serde_json::from_slice(&readable(&envelope[m.value.clone()])).ok()?;
            judged.insert(key.to_string(), value);
        }
    }
    if let Some(m) = last(&members, "error") {
        // A JSON value spelled from `n` is `null`.
        let error = if envelope[m.value.start] == b'n' {
            Value::Null
        } else {
            Value::Bool(true)
        };
        judged.insert("error".to_string(), error);
    }
    let result = last(&members, "result").map(|m| m.value.clone());
    if result.is_some() {
        judged.insert("result".to_string(), Value::Null);
    }
    Some((Value::Object(judged), result))
}

/// The caller's reply: `result` (the far end's bytes, spliced) under the caller's own `id`.
#[must_use]
pub fn result_reply(id: &Value, result: &[u8]) -> Vec<u8> {
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
        return Ok(result_reply(id, b"null"));
    }
    let span = document(body).ok_or_else(|| "the answer is not JSON".to_string())?;
    serde_json::from_slice::<serde::de::IgnoredAny>(&readable(&body[span.clone()]))
        .map_err(|e| format!("the answer is not JSON: {e}"))?;
    Ok(result_reply(id, &body[span]))
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
    fn put(
        &mut self,
        b: &[u8],
        obj: &Range<usize>,
        ms: &[ObjectMember],
        key: &str,
        value: Vec<u8>,
    ) {
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

/// The span of every item of the array spanning `span` (`b[span.start]` is `[`), in byte order.
fn array_items(b: &[u8], span: &Range<usize>) -> Option<Vec<Range<usize>>> {
    if b.get(span.start) != Some(&b'[') {
        return None;
    }
    let mut out = Vec::new();
    let mut j = past_blank(b, span.start + 1);
    while j < span.end - 1 {
        let item = value_at(b, j)?;
        j = past_blank(b, item.end);
        out.push(item);
        if b.get(j) == Some(&b',') {
            j = past_blank(b, j + 1);
        }
    }
    Some(out)
}

/// The string the JSON value at `span` spells, when it is one.
fn string_at(b: &[u8], span: &Range<usize>) -> Option<String> {
    if b.get(span.start) != Some(&b'"') {
        return None;
    }
    serde_json::from_slice(&b[span.clone()]).ok()
}

/// Every string of the array spanning `list` that `to` answers for, replaced by its answer.
fn translate_list(
    b: &[u8],
    list: &Range<usize>,
    to: &dyn Fn(&str) -> Option<String>,
    e: &mut Edits,
) {
    for item in array_items(b, list).unwrap_or_default() {
        if let Some(id) = string_at(b, &item).and_then(|s| to(&s)) {
            e.set(item, json_str(&id));
        }
    }
}

/// The members a message names the tasks it refers to under (A2A `Message.reference_task_ids`,
/// a2a.proto:276, in either spelling).
pub const REFERENCE_MEMBERS: [&str; 2] = ["referenceTaskIds", "reference_task_ids"];

/// A message's identity: its `taskId` and `contextId`, where it names them, are busbar's, and every
/// task it refers to that `refer` knows is named by busbar's id.
fn message_identity(
    b: &[u8],
    msg: &Range<usize>,
    (task_id, context_id): (&str, &str),
    refer: &dyn Fn(&str) -> Option<String>,
    e: &mut Edits,
) {
    let Some(ms) = object_members(b, msg) else {
        return;
    };
    for m in &ms {
        match m.key.as_str() {
            "taskId" => e.set(m.value.clone(), json_str(task_id)),
            "contextId" => e.set(m.value.clone(), json_str(context_id)),
            key if REFERENCE_MEMBERS.contains(&key) => translate_list(b, &m.value, refer, e),
            _ => {}
        }
    }
}

/// A table of `(name, identity member)` pairs: [`crate::task_identity::WRAPPERS`] (a wrapper and
/// the member naming the task inside it) or [`crate::task_identity::KINDS`] (a `kind` and the
/// member naming its task).
pub type IdMembers<'a> = &'a [(&'a str, &'a str)];

/// THE BYTE TWIN OF `task_identity::rewrite_identity`: the far end's `result` bytes with busbar's
/// task and context ids (and the matched skill) spliced in, every other byte as the far end wrote
/// it. The task's identity member is the one its wrapper names (`wrappers`), or, unwrapped, the one
/// its `kind` names (`kinds`), else `id`. A task a message refers to is named by busbar's id where
/// the far end's is this task's own or one of `references` (each the far end's id, then busbar's).
/// `None` when `result` is not an object.
#[must_use]
pub fn rewrite_identity(
    result: &[u8],
    (wrappers, kinds): (IdMembers<'_>, IdMembers<'_>),
    task_id: &str,
    context_id: &str,
    skill: Option<(&str, &str)>,
    references: &[(String, String)],
) -> Option<Vec<u8>> {
    let b = result;
    let top = document(b)?;
    let top_ms = object_members(b, &top)?;
    let wrapped = wrappers.iter().find_map(|(w, id)| {
        last(&top_ms, w)
            .filter(|m| b[m.value.start] == b'{')
            .map(|m| (*w, *id, m.value.clone()))
    });
    let kind = last(&top_ms, "kind").and_then(|m| string_at(b, &m.value));
    let (wrapper, id_member, payload) = match wrapped {
        Some((w, id, span)) => (Some(w), id, span),
        None => {
            let by_kind = kinds
                .iter()
                .find(|(k, _)| Some(*k) == kind.as_deref())
                .map_or("id", |(_, id)| *id);
            (None, by_kind, top)
        }
    };
    let message = match wrapper {
        Some(w) => w == "message",
        None => kind.as_deref() == Some("message"),
    };
    let ms = object_members(b, &payload)?;
    // The far end's own id for this task, read before busbar's replaces it.
    let own = last(&ms, id_member).and_then(|m| string_at(b, &m.value));
    let refer = |far: &str| {
        if own.as_deref() == Some(far) {
            return Some(task_id.to_string());
        }
        references
            .iter()
            .find(|(theirs, _)| theirs == far)
            .map(|(_, ours)| ours.clone())
    };
    let mut e = Edits::default();
    // A standalone message names no task: `taskId` is added only to one that belongs to a task.
    if !message || last(&ms, "taskId").is_some() {
        e.put(b, &payload, &ms, id_member, json_str(task_id));
    }
    e.put(b, &payload, &ms, "contextId", json_str(context_id));
    for m in ms
        .iter()
        .filter(|m| REFERENCE_MEMBERS.contains(&m.key.as_str()))
    {
        translate_list(b, &m.value, &refer, &mut e);
    }
    if let Some(status) = last(&ms, "status").filter(|m| b[m.value.start] == b'{') {
        if let Some(msg) = object_members(b, &status.value)
            .as_deref()
            .and_then(|s| last(s, "message"))
            .filter(|m| b[m.value.start] == b'{')
        {
            message_identity(b, &msg.value, (task_id, context_id), &refer, &mut e);
        }
    }
    if let Some(history) = last(&ms, "history").filter(|m| b[m.value.start] == b'[') {
        for item in array_items(b, &history.value)? {
            if b[item.start] == b'{' {
                message_identity(b, &item, (task_id, context_id), &refer, &mut e);
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
                let meta_ms = object_members(b, &span)?;
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

/// THE CALLER'S REQUEST `envelope` WITH THE TASK IDS `to` ANSWERS FOR SPLICED IN, every other byte
/// as the caller wrote it: each string member of `params` named in `top`, each of its `message`'s
/// named in `message`, and each id in the message's [`REFERENCE_MEMBERS`] lists. `None` when
/// nothing was translated (or `envelope` is not an object whose `params` is one).
#[must_use]
pub fn translate_ids(
    envelope: &[u8],
    top: &[&str],
    message: &[&str],
    to: &dyn Fn(&str) -> Option<String>,
) -> Option<Vec<u8>> {
    let b = envelope;
    let doc = document(b)?;
    let params = last(&object_members(b, &doc)?, "params")?.value.clone();
    let params_ms = object_members(b, &params)?;
    let mut e = Edits::default();
    let strings = |ms: &[ObjectMember], keys: &[&str], e: &mut Edits| {
        for m in ms.iter().filter(|m| keys.contains(&m.key.as_str())) {
            if let Some(id) = string_at(b, &m.value).and_then(|s| to(&s)) {
                e.set(m.value.clone(), json_str(&id));
            }
        }
    };
    strings(params_ms.as_slice(), top, &mut e);
    if let Some(msg) = last(&params_ms, "message").filter(|m| b[m.value.start] == b'{') {
        if let Some(msg_ms) = object_members(b, &msg.value) {
            strings(msg_ms.as_slice(), message, &mut e);
            for m in msg_ms
                .iter()
                .filter(|m| REFERENCE_MEMBERS.contains(&m.key.as_str()))
            {
                translate_list(b, &m.value, to, &mut e);
            }
        }
    }
    if e.replace.is_empty() {
        return None;
    }
    Some(e.apply(b))
}

#[cfg(test)]
#[path = "tests/answer_bytes_tests.rs"]
mod tests;
