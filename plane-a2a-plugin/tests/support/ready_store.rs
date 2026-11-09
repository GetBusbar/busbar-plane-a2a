// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Read-only restarted-store fixture for actual READY crossings. The quota gate is already
//! initialized; fresh-store bootstrap and conditional publication have their own regressions.

use std::sync::Arc;

use busbar_contract::ids::RecordSchemaId;
use busbar_contract::kinds::{RecordBytes, StoreError};
use busbar_kernel::host_records::{record_key, RecordRows};
use busbar_kernel::host_services::{InstanceFacts, KernelServices, Offload};

struct ReadyRecords {
    instance: &'static str,
    stray_card_part: bool,
}

impl RecordRows for ReadyRecords {
    fn record_put(&self, _: RecordSchemaId, _: &[u8], _: &RecordBytes) -> Result<(), StoreError> {
        panic!("a restarted READY must not rewrite its quota gate")
    }

    fn record_get(
        &self,
        schema: RecordSchemaId,
        key: &[u8],
    ) -> Result<Option<RecordBytes>, StoreError> {
        Ok(
            (schema.as_str() == "task_quota" && key == record_key(self.instance, b"active/v1"))
                .then(|| {
                    RecordBytes::new(br#"{"version":1,"epoch":1,"active":0}"#.to_vec()).unwrap()
                }),
        )
    }

    fn record_scan(
        &self,
        schema: RecordSchemaId,
        prefix: &[u8],
        limit: u32,
    ) -> Result<Vec<(Vec<u8>, RecordBytes)>, StoreError> {
        let key = record_key(self.instance, b"vendor/0123456789abcdef/0");
        if self.stray_card_part
            && schema.as_str() == "card"
            && key.starts_with(prefix)
            && limit != 0
        {
            Ok(vec![(key, RecordBytes::new(b"{}".to_vec()).unwrap())])
        } else {
            Ok(Vec::new())
        }
    }

    fn claim(&self, _: &str, _: &str, _: u64, _: u64) -> Result<bool, StoreError> {
        panic!("read-only READY does not claim")
    }
}

struct Inline;
impl Offload for Inline {
    fn run(&self, job: Box<dyn FnOnce() + Send>) {
        job();
    }
}

pub fn services(instance: &'static str, stray_card_part: bool) -> KernelServices {
    let services = KernelServices::new()
        .with_records(Arc::new(ReadyRecords {
            instance,
            stray_card_part,
        }))
        .with_pool(Arc::new(Inline));
    futures::executor::block_on(
        services.admit(
            instance,
            InstanceFacts {
                record_kinds: ["task_quota", "card", "card_approval"]
                    .into_iter()
                    .map(RecordSchemaId::new)
                    .collect(),
                ..Default::default()
            },
        ),
    )
    .expect("admit read-only READY record namespaces");
    services
}
