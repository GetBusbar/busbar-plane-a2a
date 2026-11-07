// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::abi::sdk::plane::conditional::{
    ConditionalCandidate, RecordMutation, RecordPredicate,
};
use busbar_contract::host_records::conditional::{Decision, Expected, Request};
use busbar_contract::host_records::RecordFailure;
use busbar_contract::ids::RecordSchemaId;
use busbar_contract::kinds::{RecordBytes, StoreError};
use busbar_kernel::host_records::{record_key, RecordRows};
use busbar_kernel::host_services::{InstanceFacts, KernelServices, Offload};

struct Inline;
impl Offload for Inline {
    fn run(&self, job: Box<dyn FnOnce() + Send>) {
        job();
    }
}

/// The store boundary records the actual host-produced request. This regression is about
/// admission negotiation, not backend persistence (covered by Store conformance).
#[derive(Default)]
struct Observed(std::sync::Mutex<Vec<Request>>);
impl RecordRows for Observed {
    fn supports_record_transaction(&self) -> bool {
        true
    }
    fn record_transaction(&self, request: &Request) -> Result<Decision, RecordFailure> {
        request
            .encode_held()
            .expect("actual host request passes wire validation");
        self.0.lock().unwrap().push(request.clone());
        Ok(Decision::Applied)
    }
    fn record_put(&self, _: RecordSchemaId, _: &[u8], _: &RecordBytes) -> Result<(), StoreError> {
        panic!("quota must never use ordinary put")
    }
    fn record_get(&self, _: RecordSchemaId, _: &[u8]) -> Result<Option<RecordBytes>, StoreError> {
        panic!("no read needed for this exact absent predicate")
    }
    fn record_scan(
        &self,
        _: RecordSchemaId,
        _: &[u8],
        _: u32,
    ) -> Result<Vec<(Vec<u8>, RecordBytes)>, StoreError> {
        panic!("no scan needed")
    }
    fn claim(&self, _: &str, _: &str, _: u64, _: u64) -> Result<bool, StoreError> {
        panic!("conditional publication does not claim")
    }
}

#[tokio::test]
async fn actual_a2a_door_negotiates_quota_through_host_conditional_publication() {
    let rows = Arc::new(Observed::default());
    let host = Arc::new(
        KernelServices::new()
            .with_records(rows.clone())
            .with_pool(Arc::new(Inline)),
    );
    let services = crate::root::serve::LateServices::new();
    services
        .install_kernel(host.clone(), host.clone())
        .expect("install actual host");
    let dispatcher = Arc::new(crate::root::dispatch::build(1, &services));
    let row = LinkedRow::of(door()).expect("actual linked A2A door");
    let plane = load_linked::<Plane>(
        &row,
        Bind {
            instance: Arc::from("quota-negotiation"),
            max_inflight_cap: 64,
            sink: Arc::new(NoSink),
            dispatcher: dispatcher.adopter(),
            conns: ConnTable::Probe,
        },
    )
    .expect("load and decode actual Statement extensions");
    let declaration = plane.declared();
    let quota = declaration
        .record_kinds
        .iter()
        .position(|kind| *kind == "task_quota")
        .expect("actual declared quota kind") as u32;
    let caller = plane.service_caller().expect("actual loader caller");
    host.admit(
        &caller.instance,
        InstanceFacts {
            record_kinds: declaration
                .record_kinds
                .iter()
                .map(|kind| RecordSchemaId::new(kind))
                .collect(),
            conditional_record_kinds: declaration.conditional_record_kinds,
            record_chains: declaration.record_chains,
            ..Default::default()
        },
    )
    .await
    .expect("admit exactly the negotiated declaration");
    let key = b"active/v1".to_vec();
    let value = br#"{"version":1,"epoch":1,"active":null}"#.to_vec();
    let (send, receive) = std::sync::mpsc::channel();
    host.record_transaction(
        &caller,
        None,
        ConditionalCandidate {
            correlation: 1,
            predicates: vec![RecordPredicate {
                kind: quota,
                key: key.clone(),
                expected: Expected::Absent,
            }],
            mutations: vec![RecordMutation::Put {
                kind: quota,
                key: key.clone(),
                value: value.clone(),
            }],
            chains: vec![],
        },
        Box::new(move |result| {
            send.send(result).unwrap();
        }),
    )
    .expect("initial quota bootstrap transaction must be negotiated");
    assert_eq!(
        receive
            .recv_timeout(std::time::Duration::from_secs(1))
            .unwrap()
            .decision,
        Ok(Decision::Applied)
    );
    let observed = rows.0.lock().unwrap();
    assert_eq!(observed.len(), 1);
    assert_eq!(observed[0].predicates[0].schema, "task_quota");
    assert_eq!(
        observed[0].predicates[0].key,
        record_key("quota-negotiation", &key)
    );
    assert_eq!(observed[0].predicates[0].expected, Expected::Absent);
    assert_eq!(
        observed[0].mutations,
        vec![busbar_contract::host_records::conditional::Mutation::Put {
            schema: "task_quota".into(),
            key: record_key("quota-negotiation", &key),
            value,
        }]
    );
}
