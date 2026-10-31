// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for the A2A relay's frame reader: the reader's own battery. Its warning capture and its
//! catalog drift guard run where the host's testkit and the published catalog are reachable.

use super::*;
use crate::tests::capture::Capture;

/// Feed `chunk` and take the events it finished, owned.
fn fed(r: &mut SseReader, chunk: &[u8]) -> Vec<String> {
    r.feed(chunk);
    r.frames().map(str::to_string).collect()
}

/// All three of the spec's line terminators end a line, so every pairing of two of them ends a frame
/// (eight distinct pairings: a CR followed by an LF is one CRLF, not a pair), each listed once —
/// mirroring the http transport's `sse::proto` test `every_spec_line_terminator_pairing_ends_a_frame`
/// over `SseReader::feed` rather than the bare scanner. A bare-CR stream (or one mixing terminators
/// across the frame boundary) must frame exactly like an LF/CRLF one.
#[test]
fn every_spec_line_terminator_pairing_ends_a_frame() {
    let cases: &[(&str, &str)] = &[
        ("data: a\r\rrest", "data: a\r\r"),
        ("data: a\n\rrest", "data: a\n\r"),
        ("data: a\r\n\rrest", "data: a\r\n\r"),
        ("data: a\n\r\nrest", "data: a\n\r\n"),
        ("data: a\r\n\n", "data: a\r\n\n"),
        ("data: a\r\r\nrest", "data: a\r\r\n"),
        ("data: a\n\nrest", "data: a\n\n"),
        ("data: a\r\n\r\nrest", "data: a\r\n\r\n"),
    ];
    for (input, framed) in cases {
        let mut r = SseReader::default();
        let out = fed(&mut r, input.as_bytes());
        assert_eq!(out, vec![framed.to_string()], "input {input:?}");
    }

    // The lone trailing CR is not yet knowable — it may still turn out to be a CRLF — so it
    // returns nothing until more bytes arrive.
    let mut r = SseReader::default();
    assert!(
        fed(&mut r, b"data: a\r").is_empty(),
        "a bare trailing CR must wait for more bytes, not frame early"
    );
}

/// The cursor rewind must not let a terminator SPLIT across a chunk boundary slip past: the longest
/// terminator is four bytes, so resuming three bytes behind the previous end is exactly enough.
/// Passes before and after the cursor exists — it guards the fix, not the defect.
#[test]
fn test_terminator_split_across_chunks_still_frames() {
    for (head, tail, framed, leftover) in [
        ("data: a\r\n", "\r\n", "data: a\r\n\r\n", ""),
        ("data: a\r\n\r", "\n", "data: a\r\n\r\n", ""),
        ("data: a\n", "\n", "data: a\n\n", ""),
        // A bare CR ending the tail is ITSELF ambiguous (it may still turn out to be a CRLF), so
        // the tail carries one more, unambiguous byte after it; that byte is not part of the
        // terminator and stays pending.
        ("data: a\r", "\rx", "data: a\r\r", "x"),
    ] {
        let mut r = SseReader::default();
        assert!(
            fed(&mut r, head.as_bytes()).is_empty(),
            "a partial terminator waits for the rest ({head:?})"
        );
        let out = fed(&mut r, tail.as_bytes());
        assert_eq!(
            out,
            vec![framed.to_string()],
            "a terminator straddling the chunk boundary still ends the event ({head:?}+{tail:?})"
        );
        assert_eq!(
            r.pending(),
            leftover.len(),
            "only the disambiguating byte (if any) stays buffered ({head:?}+{tail:?})"
        );
    }
}

/// A frame that was framed by a bare-CR terminator must still split into fields on a bare-CR line
/// break — `str::lines()` only splits on LF/CRLF, so a bare-CR frame yielded NO data at all (any
/// caller relaying a real event feed got nothing back and had to fail the exchange upstream), and a
/// multi-field bare-CR frame swallowed later fields into the first value.
#[test]
fn test_sse_data_splits_on_bare_cr() {
    assert_eq!(
        sse_data("event: message\rdata: {\"a\":1}\r\r"),
        Some("{\"a\":1}".to_string())
    );
    // Two `data:` lines joined by a bare CR must still concatenate with `\n`, not swallow the
    // second line into the first's value.
    assert_eq!(
        sse_data("data: line1\rdata: line2\r\r"),
        Some("line1\nline2".to_string())
    );
    // LF and CRLF frames stay byte-identical to today.
    assert_eq!(
        sse_data("event: message\ndata: {\"a\":1}\n\n"),
        Some("{\"a\":1}".to_string())
    );
    assert_eq!(
        sse_data("data: line1\r\ndata: line2\r\n\r\n"),
        Some("line1\nline2".to_string())
    );
}

/// Ported from busbar-a2a tests/sse_tests.rs::test_non_utf8_frame_drop_carries_diag_code.
/// A dropped non-UTF-8 frame is an operator-facing warn on a served path, so it carries a
/// registered `BUSBAR-NNNN` code an operator can look up; the drop itself is unchanged. Emitted
/// twice because a warn callsite's interest is cached process-wide and a concurrent test's
/// dispatcher can make the FIRST emission through this scoped subscriber invisible.
#[test]
fn test_non_utf8_frame_drop_carries_diag_code() {
    let (sent, heard) = std::sync::mpsc::channel();
    let out = tracing::subscriber::with_default(Capture(sent), || {
        let mut r = SseReader::default();
        let first = fed(&mut r, b"data: \xff\xfe\n\n");
        let _ = fed(&mut r, b"data: \xff\xfe\n\n");
        first
    });
    assert!(
        out.is_empty(),
        "a non-UTF-8 frame is still dropped, not relayed"
    );
    let banner = PLANE_SSE_FRAME_NOT_UTF8.banner().to_string();
    let seen: Vec<String> = heard
        .try_iter()
        .filter(|(level, _)| *level == tracing::Level::WARN)
        .map(|(_, line)| line)
        .collect();
    assert!(
        seen.iter().any(|line| line.contains(&banner)),
        "the dropped-frame warning must carry diag={banner}; captured: {seen:?}"
    );
    assert!(
        seen.iter()
            .any(|line| line.contains("dropping a non-UTF-8 SSE frame")),
        "the message text is preserved; captured: {seen:?}"
    );
}
