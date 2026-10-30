// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The A2A relay's SSE (Server-Sent Events) frame reader, the plane's own.
//!
//! Bytes in, whole events out: an SSE stream does not arrive one event per chunk, so bytes
//! accumulate here and an event is emitted only on the blank line that terminates it. The relay's
//! streaming legs (JSON-RPC and REST) are its only consumers, so it is dialect
//! machinery that lives with the plane rather than in a neutral crate. The line-terminator grammar it
//! frames on is the contract's ([`busbar_contract::protocol::find_frame_terminator`] and
//! [`busbar_contract::protocol::sse_lines`]), shared with every other SSE reader in the tree.
//!
//! The one coded diagnostic it prints, [`PLANE_SSE_FRAME_NOT_UTF8`], is the plane's too.
//! Its number and text are the published catalog entry's, field for field (`docs/diagnostics.json`;
//! the drift test beside this module fails if they part).

pub use crate::diagnostics::PLANE_SSE_FRAME_NOT_UTF8;

use std::ops::Range;

/// THE SSE FRAME READER: bytes in, whole events out, borrowed from its own buffer. The reassembly
/// (an event arrives across chunks, several in one, or split mid-terminator) is the contract's
/// [`busbar_contract::protocol::SseFrames`]; this reader keeps the frames a feed finished and drops
/// a non-UTF-8 one with [`PLANE_SSE_FRAME_NOT_UTF8`].
#[derive(Debug, Clone, Default)]
pub struct SseReader {
    buf: busbar_contract::protocol::SseFrames,
    /// The spans in the reassembler's buffer of the events the last [`Self::feed`] finished
    /// ([`Self::frames`]).
    frames: Vec<Range<usize>>,
}

impl SseReader {
    /// Feed a chunk: every COMPLETE event it finished is then [`Self::frames`].
    pub fn feed(&mut self, chunk: &[u8]) {
        self.frames.clear();
        self.buf.push(chunk);
        while let Some(frame) = self.buf.next_span() {
            match std::str::from_utf8(&self.buf.buffer()[frame.clone()]) {
                Ok(_) => self.frames.push(frame),
                // The event-stream format is UTF-8 by definition: a non-UTF-8 frame is a malformed
                // backend, dropped (never lossily relayed) and surfaced.
                Err(_) => busbar_contract::diag_warn!(
                    PLANE_SSE_FRAME_NOT_UTF8,
                    bytes = frame.len(),
                    "dropping a non-UTF-8 SSE frame (the event-stream format requires UTF-8)"
                ),
            }
        }
    }

    /// The events the last [`Self::feed`] finished, in order, each borrowed from the reader's
    /// buffer (none copied out).
    pub fn frames(&self) -> impl Iterator<Item = &str> {
        self.frames
            .iter()
            .filter_map(|frame| std::str::from_utf8(&self.buf.buffer()[frame.clone()]).ok())
    }

    /// How many bytes are held waiting for a terminator. The ceiling check reads this: a backend
    /// that streams megabytes with no blank line is an unbounded allocation it chose the size of.
    pub fn pending(&self) -> usize {
        self.buf.pending()
    }
}

/// The `data:` payload of one SSE frame, concatenated across continuation lines as the specification
/// requires. Splits on [`busbar_contract::protocol::sse_lines`], the grammar-based splitter (CRLF, lone LF, or
/// lone CR each end a line) — `str::lines()` does not split on a bare CR, so a bare-CR frame
/// yielded no data at all.
pub fn sse_data(frame: &str) -> Option<String> {
    let mut data = String::new();
    let mut any = false;
    for line in busbar_contract::protocol::sse_lines(frame) {
        // A `data:`-prefixed line carries the value after the colon; a BARE `data` line (no colon)
        // is a `data` field with an EMPTY value per the event-stream format — both contribute to the
        // payload (the bare form as an empty continuation line), so recognise both.
        let rest = if let Some(rest) = line.strip_prefix("data:") {
            rest
        } else if line == "data" {
            ""
        } else {
            continue;
        };
        if any {
            data.push('\n');
        }
        any = true;
        data.push_str(rest.strip_prefix(' ').unwrap_or(rest));
    }
    any.then_some(data)
}

#[cfg(test)]
#[path = "tests/sse_tests.rs"]
mod tests;
