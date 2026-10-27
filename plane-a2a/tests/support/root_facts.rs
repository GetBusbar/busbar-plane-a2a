// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! WHAT THE ROOT LEG (`tests/root/mod.rs`) NAMES OF THE PLANE'S PRIVATE ITEMS. The root leg is
//! compiled into the composition root's test binary and reaches the plane only through `door`
//! (the crate's one public item), so the facts it needs are carried here as plain data and the
//! protobuf messages it sends and reads are written on the wire directly, with no generated type.
//! The crate's own unit test `door_facts` (`src/tests/door_facts.rs`) includes this same file and
//! holds every value to the private item it restates and every helper to the generated message
//! it stands for, so a drift is red in the crate before the root leg reads a stale copy.

/// `door_statement::PUSH_SECTION`: the plane's own `agent_push:` section.
pub const PUSH_SECTION: &str = "agent_push";

/// `door_statement::PUSH_CA_KEY`: the [`PUSH_SECTION`] key holding the operator CA.
pub const PUSH_CA_KEY: &str = "ca";

/// `door_statement::PUSH_TRUST_FROM`: where the push need's trust anchor comes from.
pub const PUSH_TRUST_FROM: &str = "owned.agent_push.ca";

/// `door_statement::NEED_AGENT`: the `NEEDS` index of the relayed calls to the registered agents.
pub const NEED_AGENT: u32 = 1;

/// `door_statement::NEED_GRPC`: the `NEEDS` index of the relayed calls to a gRPC-bound agent.
pub const NEED_GRPC: u32 = 2;

/// `proto::SERVICE_NAME`: the gRPC service's full name.
pub const SERVICE_NAME: &str = "lf.a2a.v1.A2AService";

/// `claims::FRAMED_TRANSPORT`: the transport the framed binding is made against.
pub const FRAMED_TRANSPORT: &str = "grpc";

/// `pb::Role::User as i32`.
pub const ROLE_USER: u64 = 1;

/// `pb::TaskState::Working as i32`.
pub const TASK_STATE_WORKING: u64 = 2;

/// One protobuf field as read off the wire: a varint, or a length-delimited run of bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Field {
    /// Wire type 0.
    Varint(u64),
    /// Wire type 2.
    Bytes(Vec<u8>),
}

fn put_varint(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let low = u8::try_from(v & 0x7f).expect("seven bits");
        v >>= 7;
        if v == 0 {
            out.push(low);
            return;
        }
        out.push(low | 0x80);
    }
}

fn put_bytes(out: &mut Vec<u8>, field: u32, data: &[u8]) {
    put_varint(out, u64::from(field << 3 | 2));
    put_varint(out, u64::try_from(data.len()).expect("a length"));
    out.extend_from_slice(data);
}

fn put_varint_field(out: &mut Vec<u8>, field: u32, v: u64) {
    put_varint(out, u64::from(field << 3));
    put_varint(out, v);
}

/// A `SendMessageRequest` carrying one user message of one text part, as protobuf.
#[must_use]
pub fn send_message_request(message_id: &str, text: &str) -> Vec<u8> {
    let mut part = Vec::new();
    put_bytes(&mut part, 1, text.as_bytes());
    let mut message = Vec::new();
    put_bytes(&mut message, 1, message_id.as_bytes());
    put_varint_field(&mut message, 4, ROLE_USER);
    put_bytes(&mut message, 5, &part);
    let mut request = Vec::new();
    put_bytes(&mut request, 2, &message);
    request
}

/// A `GetTaskRequest` naming task `id`, as protobuf.
#[must_use]
pub fn get_task_request(id: &str) -> Vec<u8> {
    let mut request = Vec::new();
    put_bytes(&mut request, 2, id.as_bytes());
    request
}

/// Every field of one message, in wire order.
///
/// # Errors
///
/// A truncated message, or a wire type other than varint and length-delimited.
pub fn fields(mut bytes: &[u8]) -> Result<Vec<(u32, Field)>, String> {
    fn varint(bytes: &mut &[u8]) -> Result<u64, String> {
        let mut v = 0u64;
        for shift in (0..64).step_by(7) {
            let (&b, rest) = bytes.split_first().ok_or("a truncated varint")?;
            *bytes = rest;
            v |= u64::from(b & 0x7f) << shift;
            if b & 0x80 == 0 {
                return Ok(v);
            }
        }
        Err("a varint longer than ten bytes".to_string())
    }
    let mut out = Vec::new();
    while !bytes.is_empty() {
        let key = varint(&mut bytes)?;
        let number = u32::try_from(key >> 3).map_err(|e| e.to_string())?;
        match key & 7 {
            0 => out.push((number, Field::Varint(varint(&mut bytes)?))),
            2 => {
                let len = usize::try_from(varint(&mut bytes)?).map_err(|e| e.to_string())?;
                if bytes.len() < len {
                    return Err("a truncated field".to_string());
                }
                let (run, rest) = bytes.split_at(len);
                bytes = rest;
                out.push((number, Field::Bytes(run.to_vec())));
            }
            other => return Err(format!("wire type {other} is not one the root leg reads")),
        }
    }
    Ok(out)
}

fn bytes_of(message: &[u8], number: u32) -> Result<Option<Vec<u8>>, String> {
    Ok(fields(message)?.into_iter().find_map(|(n, f)| match f {
        Field::Bytes(b) if n == number => Some(b),
        _ => None,
    }))
}

fn text(bytes: Vec<u8>) -> Result<String, String> {
    String::from_utf8(bytes).map_err(|e| e.to_string())
}

/// The message a `SendMessageRequest` carried: its id, its role's number, its text parts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SentMessage {
    /// `Message.message_id`.
    pub message_id: String,
    /// `Message.role`, as its number.
    pub role: u64,
    /// The `text` of each part that has one, in order.
    pub texts: Vec<String>,
}

/// Read a `SendMessageRequest`'s message.
///
/// # Errors
///
/// Bytes that are not a `SendMessageRequest` carrying a message.
pub fn read_send_message_request(request: &[u8]) -> Result<SentMessage, String> {
    let message = bytes_of(request, 2)?.ok_or("the request carries no message")?;
    let mut read = SentMessage {
        message_id: String::new(),
        role: 0,
        texts: Vec::new(),
    };
    for (number, field) in fields(&message)? {
        match (number, field) {
            (1, Field::Bytes(id)) => read.message_id = text(id)?,
            (4, Field::Varint(role)) => read.role = role,
            (5, Field::Bytes(part)) => {
                if let Some(t) = bytes_of(&part, 1)? {
                    read.texts.push(text(t)?);
                }
            }
            _ => {}
        }
    }
    Ok(read)
}

/// The `TaskState` number of the task a `SendMessageResponse` carried.
///
/// # Errors
///
/// Bytes that are not a `SendMessageResponse` carrying a task with a status.
pub fn send_message_response_task_state(response: &[u8]) -> Result<u64, String> {
    let task = bytes_of(response, 1)?.ok_or("the response carries no task")?;
    let status = bytes_of(&task, 3)?.ok_or("the task carries no status")?;
    fields(&status)?
        .into_iter()
        .find_map(|(n, f)| match f {
            Field::Varint(state) if n == 1 => Some(state),
            _ => None,
        })
        .ok_or_else(|| "the status carries no state".to_string())
}
