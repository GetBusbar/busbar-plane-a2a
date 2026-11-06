// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use busbar_kernel::host_services::{Admitted, DestJudge, DestRefusal, Destination};

/// Records the real destination guard's decisions without changing any of them.
pub(super) struct Destinations {
    inner: Arc<dyn DestJudge>,
    decisions: Arc<Mutex<Vec<(String, bool)>>>,
}

impl Destinations {
    pub(super) fn new(inner: Arc<dyn DestJudge>) -> Self {
        Self {
            inner,
            decisions: Arc::default(),
        }
    }

    pub(super) fn decisions(&self) -> Vec<(String, bool)> {
        self.decisions
            .lock()
            .expect("destination decisions")
            .clone()
    }

    fn record(&self, dest: &str, admitted: bool) {
        self.decisions
            .lock()
            .expect("destination decisions")
            .push((dest.to_string(), admitted));
    }

    fn completion(
        &self,
        dest: &str,
        done: Box<dyn FnOnce(Admitted) + Send>,
    ) -> Box<dyn FnOnce(Admitted) + Send> {
        let decisions = Arc::clone(&self.decisions);
        let dest = dest.to_string();
        Box::new(move |answer| {
            decisions
                .lock()
                .expect("destination decisions")
                .push((dest, answer.is_ok()));
            done(answer);
        })
    }
}

impl DestJudge for Destinations {
    fn judge_target_name(&self, target: Destination<'_>, refuse_private: bool) -> Result<(), u64> {
        let answer = self.inner.judge_target_name(target, refuse_private);
        self.record(target.authority, answer.is_ok());
        answer
    }

    fn judge_target(
        &self,
        target: Destination<'_>,
        refuse_private: bool,
        reach: bool,
        done: Box<dyn FnOnce(Admitted) + Send>,
    ) -> Option<Admitted> {
        let answer = self.inner.judge_target(
            target,
            refuse_private,
            reach,
            self.completion(target.authority, done),
        );
        if let Some(answer) = &answer {
            self.record(target.authority, answer.is_ok());
        }
        answer
    }

    fn judge_name(&self, dest: &str, class: u32, refuse_private: bool) -> Result<(), u64> {
        let answer = self.inner.judge_name(dest, class, refuse_private);
        self.record(dest, answer.is_ok());
        answer
    }

    fn judge(
        &self,
        dest: &str,
        class: u32,
        refuse_private: bool,
        done: Box<dyn FnOnce(Admitted) + Send>,
    ) -> Option<Admitted> {
        let answer = self
            .inner
            .judge(dest, class, refuse_private, self.completion(dest, done));
        if let Some(answer) = &answer {
            self.record(dest, answer.is_ok());
        }
        answer
    }

    fn judge_reaching(
        &self,
        dest: &str,
        class: u32,
        done: Box<dyn FnOnce(Admitted) + Send>,
    ) -> Option<Admitted> {
        let answer = self
            .inner
            .judge_reaching(dest, class, self.completion(dest, done));
        if let Some(answer) = &answer {
            self.record(dest, answer.is_ok());
        }
        answer
    }

    fn judge_answer(&self, host: &str, addrs: &[IpAddr], class: u32) -> Result<(), DestRefusal> {
        let answer = self.inner.judge_answer(host, addrs, class);
        self.record(host, answer.is_ok());
        answer
    }

    fn judge_host(&self, host: &str, class: u32) -> Result<(), DestRefusal> {
        let answer = self.inner.judge_host(host, class);
        self.record(host, answer.is_ok());
        answer
    }

    fn destinations_applied(&self, destinations: &busbar_kernel::config::Destinations) {
        self.inner.destinations_applied(destinations);
    }
}
