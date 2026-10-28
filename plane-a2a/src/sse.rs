// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE A2A RELAY'S SSE (Server-Sent Events) FRAME READER — the plane's own (#83a, SD-5c).
//!
//! Bytes in, whole events out: an SSE stream does not arrive one event per chunk, so bytes
//! accumulate here and an event is emitted only on the blank line that terminates it. The relay's
//! streaming legs (JSON-RPC and REST) are its only consumers, so it is dialect
//! machinery that lives with the plane rather than in a neutral crate. The line-terminator grammar it
//! frames on is the contract's ([`busbar_contract::protocol::find_frame_terminator`] and
//! [`busbar_contract::protocol::sse_lines`]), shared with every other SSE reader in the tree.
//!
//! The one coded diagnostic it prints, [`PLANE_SSE_FRAME_NOT_UTF8`], is the plane's too (#83a O4).
//! Its number and text are the published catalog entry's, field for field (`docs/diagnostics.json`;
//! the drift test beside this module fails if they part).

pub use crate::diagnostics::PLANE_SSE_FRAME_NOT_UTF8;

use std::ops::Range;

/// THE SSE FRAME READER: bytes in, whole events out, borrowed from its own buffer.
///
/// A separate type rather than a closure because an SSE stream does NOT arrive one event per chunk.
/// A single TCP read can carry three events, half an event, or the tail of one and the head of the
/// next, and a reader that assumed a chunk was an event would corrupt a caller's stream under
/// exactly the conditions that are hardest to reproduce. So bytes accumulate here and an event is
/// emitted only on the blank line that terminates it.
#[derive(Debug, Clone, Default)]
pub struct SseReader {
    buf: Vec<u8>,
    /// The spans in `buf` of the events the last [`Self::feed`] finished ([`Self::frames`]).
    frames: Vec<Range<usize>>,
    /// The front of `buf` the last feed framed: dropped by the next feed, once its frames are done
    /// with.
    framed: usize,
    /// How far into `buf` a terminator scan has already looked and found nothing. A stream that
    /// trickles one event across many chunks would otherwise re-walk the WHOLE accumulated buffer on
    /// every chunk — quadratic in the event's size, on a relay thread fed by an untrusted upstream
    /// whose only bound is the megabyte-scale body cap. Moved back with the front-drain, because the
    /// bytes after the framed front have never been scanned in their new positions.
    scanned: usize,
}

/// The longest terminator (`\r\n\r\n`) is four bytes, so a scan that resumes THREE bytes behind the
/// previous end still sees any terminator that straddles the boundary between two chunks.
const TERMINATOR_REWIND: usize = 3;

impl SseReader {
    /// Feed a chunk: every COMPLETE event it finished is then [`Self::frames`].
    ///
    /// Walks the framed front across `buf` and drains it ONCE, at the next feed, rather than
    /// draining from the front once PER FRAME: `Vec::drain` from the front memmoves the entire
    /// remaining tail, so draining per frame cost O(frames × bytes) on a chunk carrying many small
    /// events (the same shape the AWS event-stream framing fixed).
    pub fn feed(&mut self, chunk: &[u8]) {
        self.drain_front();
        self.frames.clear();
        self.buf.extend_from_slice(chunk);
        // Resume where the last scan stopped (minus the rewind): nothing before this point can hold
        // the earliest terminator, since that region was already searched and every terminator it
        // could still complete extends into the rewind window.
        let mut scan_from = self.scanned.saturating_sub(TERMINATOR_REWIND);
        while let Some((rel, len)) = {
            #[cfg(test)]
            tests::tally(&tests::SCANNED, self.buf.len() - scan_from);
            busbar_contract::protocol::find_frame_terminator(&self.buf[scan_from..])
        } {
            let end = scan_from + rel + len;
            let frame = self.framed..end;
            match std::str::from_utf8(&self.buf[frame.clone()]) {
                Ok(_) => self.frames.push(frame),
                // The event-stream format is UTF-8 by definition, so a non-UTF-8 frame is a
                // malformed backend. Dropping it (rather than lossily corrupting the payload) is
                // correct, but doing so SILENTLY hid the malformed stream — surface it so the drop
                // is diagnosable rather than a mystery missing event.
                Err(_) => busbar_contract::diag_warn!(
                    PLANE_SSE_FRAME_NOT_UTF8,
                    bytes = frame.len(),
                    "dropping a non-UTF-8 SSE frame (the event-stream format requires UTF-8)"
                ),
            }
            self.framed = end;
            scan_from = end;
        }
        self.scanned = self.buf.len();
    }

    /// Drop the framed front — THE ONE front-drain in this reader, once per feed at most.
    fn drain_front(&mut self) {
        if self.framed == 0 {
            return;
        }
        #[cfg(test)]
        tests::tally(&tests::DRAINED, self.buf.len());
        self.buf.drain(..self.framed);
        self.scanned -= self.framed;
        self.framed = 0;
    }

    /// The events the last [`Self::feed`] finished, in order, each borrowed from the reader's
    /// buffer (none copied out).
    pub fn frames(&self) -> impl Iterator<Item = &str> {
        self.frames
            .iter()
            .filter_map(|frame| std::str::from_utf8(&self.buf[frame.clone()]).ok())
    }

    /// How many bytes are held waiting for a terminator. The ceiling check reads this: a backend
    /// that streams megabytes with no blank line is an unbounded allocation it chose the size of.
    pub fn pending(&self) -> usize {
        self.buf.len() - self.framed
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
