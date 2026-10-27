// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The tests' one `tracing` capture.

/// Every event's level and rendered fields, sent down a channel (the plane holds no subscriber
/// dependency, so the `tracing` trait is implemented by hand). Admits every level, so an assertion
/// holds whichever side of an error-once latch this process is on.
pub(crate) struct Capture(pub(crate) std::sync::mpsc::Sender<(tracing::Level, String)>);

struct Render<'a>(&'a mut String);

impl tracing::field::Visit for Render<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        use std::fmt::Write as _;
        let _ = write!(self.0, "{}={value:?} ", field.name());
    }
}

impl tracing::Subscriber for Capture {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        let mut line = String::new();
        event.record(&mut Render(&mut line));
        let _ = self.0.send((*event.metadata().level(), line));
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}
