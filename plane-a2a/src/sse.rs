// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The A2A relay's SSE (Server-Sent Events) frame reader, the plane's own.

pub use crate::diagnostics::PLANE_SSE_FRAME_NOT_UTF8;

use std::ops::Range;

/// THE SSE FRAME READER: bytes in, whole events out, borrowed from its own buffer. The reassembly
/// (an event arrives across chunks, several in one, or split mid-terminator) is the contract's
/// [`busbar_contract::protocol::SseFrames`]; this reader keeps the frames a feed finished and drops
/// a non-UTF-8 one with [`PLANE_SSE_FRAME_NOT_UTF8`].
#[derive(Debug, Clone, Default)]
pub struct SseReader {
    buf: busbar_contract::protocol::SseFrames,
    backend: String,
    /// The spans in the reassembler's buffer of the events the last [`Self::feed`] finished
    /// ([`Self::frames`]).
    frames: Vec<Range<usize>>,
}

impl SseReader {
    /// Feed the relayed backend's bytes with its registered name for operator diagnostics.
    pub fn feed_from(&mut self, backend: &str, chunk: &[u8]) {
        self.backend.clear();
        self.backend.push_str(backend);
        self.feed(chunk);
    }

    /// Feed a chunk: every COMPLETE event it finished is then [`Self::frames`].
    pub fn feed(&mut self, chunk: &[u8]) {
        self.frames.clear();
        self.buf.push(chunk);
        while let Some(frame) = self.buf.next_span() {
            match std::str::from_utf8(&self.buf.buffer()[frame.clone()]) {
                Ok(_) => self.frames.push(frame),

                Err(_) => busbar_contract::diag_warn!(
                    PLANE_SSE_FRAME_NOT_UTF8,
                    agent = %self.backend,
                    bytes = frame.len(),
                    "dropping a non-UTF-8 SSE frame (the event-stream format requires UTF-8)"
                ),
            }
        }
    }

    /// The events the last [`Self::feed`] finished, in order, each borrowed from the reader's
    pub fn frames(&self) -> impl Iterator<Item = &str> {
        self.frames
            .iter()
            .filter_map(|frame| std::str::from_utf8(&self.buf.buffer()[frame.clone()]).ok())
    }

    /// How many bytes are held waiting for a terminator. The ceiling check reads this: a backend
    pub fn pending(&self) -> usize {
        self.buf.pending()
    }
}

/// The `data:` payload of one SSE frame, concatenated across continuation lines as the specification
pub fn sse_data(frame: &str) -> Option<String> {
    let mut data = crate::relay::RawBytes::default();
    let mut any = false;
    for line in busbar_contract::protocol::sse_lines(frame) {
        let rest = if let Some(rest) = line.strip_prefix("data:") {
            rest
        } else if line == "data" {
            ""
        } else {
            continue;
        };
        if any {
            data.extend_from_slice(b"\n");
        }
        any = true;
        data.extend_from_slice(rest.strip_prefix(' ').unwrap_or(rest).as_bytes());
    }
    any.then(|| {
        String::from_utf8(data.into_vec())
            .expect("SSE data concatenates UTF-8 lines with UTF-8 separators")
    })
}

#[cfg(test)]
#[path = "tests/sse_tests.rs"]
mod tests;
