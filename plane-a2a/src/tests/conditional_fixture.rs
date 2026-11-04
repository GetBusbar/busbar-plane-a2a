// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The listing unit fixture's kernel model.

use super::*;

pub(crate) fn receipt(
    journal: &Journal,
    apply: impl FnOnce(&wire::Request) -> Decision,
) -> Vec<u8> {
    enum Intent {
        Observe(wire::Observation),
        Publish(Guard<wire::Request>),
    }
    let intent = journal.0.with_all(|all| {
        let state = all.get_mut(&()).expect("entered journal");
        let step = state
            .steps
            .iter_mut()
            .find(|step| step.pending())
            .expect("pending intent");
        step.submitted = true;
        match &step.action {
            Action::Observe { request, .. } => Intent::Observe(request.clone()),
            Action::Publish { request, .. } => Intent::Publish(Guard::new(request.clone())),
        }
    });
    match intent {
        Intent::Observe(request) => wire::encode_observed(
            &request,
            &wire::ObservationResult {
                correlation: request.correlation,
                result: Ok(Expected::Absent),
            },
        )
        .unwrap(),
        Intent::Publish(request) => wire::encode_result(
            &request,
            &wire::ConditionalResult {
                correlation: request.candidate.correlation,
                decision: Ok(apply(&request)),
            },
        )
        .unwrap(),
    }
}
