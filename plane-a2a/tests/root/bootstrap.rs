// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Provision a genuinely new durable namespace, migrate it through the actual plane, then
//! reopen it without a bootstrap grant for the ordinary serving and reload assertions.

use std::path::Path;
use std::time::Duration;

use busbar_kernel::host_record_bootstrap::{ColdRecordReceipt, StoreWitness};

const SCHEMA: &str = "test.fixture.a2a-creation";
const WITNESS_KEY: &[u8] = b"namespace";

pub(super) fn create(directory: &Path, settings: &serde_json::Value) {
    let database = directory.join("governance.sqlite");
    assert_eq!(
        settings["db_path"].as_str(),
        database.to_str(),
        "migration and serving must reopen the same actual durable Store"
    );
    for suffix in ["governance.sqlite-wal", "governance.sqlite-shm"] {
        assert!(
            !directory.join(suffix).exists(),
            "no retained Store sidecars"
        );
    }
    drop(
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&database)
            .expect("exclusively create this fixture's database before its first Store open"),
    );
    let creation = serde_json::json!({
        "database": database, "fixture": directory,
        "creation": "exclusive create_new before first Store open",
        "sender_quiesced": true, "backend_quiesced": true,
    });
    std::fs::write(
        directory.join("namespace-creation.json"),
        serde_json::to_vec(&creation).unwrap(),
    )
    .expect("retain actual namespace creation provenance");
}

pub(super) fn initialize(
    instance: &str,
    directory: &Path,
    config: &busbar_kernel::config::RootCfg,
    plugins: &busbar_kernel::config::PluginsCfg,
    core: &std::sync::Arc<busbar_kernel::persistence::facade::CoreStore>,
    deployment: &serde_json::Value,
) -> ColdRecordReceipt {
    let anchor = serde_json::to_value(&config.store).expect("actual effective Store selection");
    let source = crate::root::loader::sign::sha256_hex(&serde_json::to_vec(deployment).unwrap());
    let run = |action: &str, input: &Path| {
        let command = crate::root::principal_transition::command(
            [
                "--principal-transition".into(),
                input.to_string_lossy().into_owned(),
                "--transition-action".into(),
                action.into(),
            ]
            .into_iter(),
        )
        .unwrap()
        .unwrap();
        let execution = futures::executor::block_on(crate::root::principal_transition::execute(
            &command, config, plugins, core, &anchor, &source, None,
        ))
        .expect("the production principal lifecycle accepts this genuinely fresh namespace");
        std::fs::write(
            directory.join(format!("principal-{action}.json")),
            serde_json::to_vec(&execution.report).unwrap(),
        )
        .unwrap();
        execution.report
    };
    let before = run("inspect", Path::new("-"));
    assert!(before["principal_receipt_head_sha256"].is_null());
    assert_eq!(before["store_ephemeral"], false);
    let rows = busbar_kernel::persistence::scoped::ScopedStore::authorized(
        core.clone(),
        instance,
        [SCHEMA.into()],
    )
    .expect("the fixture authorizes its own public witness schema");
    let creation = std::fs::read(directory.join("namespace-creation.json")).unwrap();
    let creation_hash = crate::root::loader::sign::sha256_hex(&creation);
    let mut random = [0u8; 32];
    getrandom::fill(&mut random).expect("fresh public witness entropy");
    let witness = busbar_contract::Secret::new(random.to_vec());
    assert_eq!(
        futures::executor::block_on(rows.put(SCHEMA, WITNESS_KEY, witness))
            .expect("commit a real public witness through the actual durable Store"),
        busbar_kernel::persistence::scoped::Outcome::Applied,
    );
    let receipt = serde_json::json!({
        "version": 2,
        "witness_binding": {"instance": instance, "private": false, "source_scope": "unscoped"},
        "store_config_sha256": before["store_config_sha256"],
        "requirements": before["requirements"],
        "witness": {"schema": SCHEMA, "key_hex": hex::encode(WITNESS_KEY),
                    "value_hex": hex::encode(random)},
        "ephemeral_instance": false, "exclusive_instance": false,
        "creation_evidence_sha256": creation_hash,
        "newly_created_namespace": true, "sender_quiesced": true, "backend_quiesced": true,
        "actor": "isolated A2A fixture namespace provisioner",
        "reason": "exclusive new database; no application senders started; actual public creation witness committed",
    });
    let receipt_path = directory.join("principal-fresh.json");
    std::fs::write(&receipt_path, serde_json::to_vec(&receipt).unwrap()).unwrap();
    run("initialize-fresh", &receipt_path);
    let after = run("inspect", Path::new("-"));
    assert!(after["principal_receipt_head_sha256"].is_string());
    assert_eq!(after["requirements"], before["requirements"]);
    let mut epoch = [0u8; 16];
    getrandom::fill(&mut epoch).expect("fresh cold migration epoch");
    ColdRecordReceipt {
        version: 1,
        epoch: hex::encode(epoch),
        instance: instance.into(),
        namespace_hex: hex::encode(busbar_kernel::host_records::record_key(instance, &[])),
        store_config_sha256: busbar_kernel::host_record_bootstrap::store_fingerprint(&anchor),
        store_witness: StoreWitness {
            schema: SCHEMA.into(),
            key_hex: hex::encode(WITNESS_KEY),
            value_hex: hex::encode(random),
        },
        sender_quiesced: true,
        backend_quiesced: true,
        actor: "isolated A2A fixture namespace provisioner".into(),
        reason: "exclusive new durable namespace, no prior sender or pending backend command"
            .into(),
    }
}

const CHILD: &str = "BUSBAR_A2A_COLD_BOOTSTRAP";
const WITNESS: &str = "A2A cold bootstrap finished";

/// The fixture child reaches this hook before constructing any application in
/// its process. Its actual namespace is then reopened by the parent process.
pub(super) fn child() {
    let Some(request) = std::env::var_os(CHILD) else {
        return;
    };
    let request: serde_json::Value = serde_json::from_str(&request.to_string_lossy())
        .expect("the parent supplied the cold fixture identity");
    let instance: &'static str = Box::leak(
        request["instance"]
            .as_str()
            .expect("cold fixture instance")
            .to_owned()
            .into_boxed_str(),
    );
    let directory = Path::new(
        request["directory"]
            .as_str()
            .expect("cold fixture directory"),
    );
    migrate_here(instance, directory);
    println!("{WITNESS}: {instance}");
    std::io::Write::flush(&mut std::io::stdout()).expect("flush the actual cold fixture witness");
    std::process::exit(0);
}

pub(super) fn migrate(instance: &'static str, directory: &Path) {
    let test = std::thread::current()
        .name()
        .expect("the fixture is driven by a named test")
        .to_owned();
    let request = serde_json::json!({"instance": instance, "directory": directory});
    let output =
        std::process::Command::new(std::env::current_exe().expect("the actual test binary"))
            .args(["--exact", &test, "--nocapture", "--test-threads=1"])
            .env(CHILD, request.to_string())
            .output()
            .expect("start the genuine cold bootstrap process");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success() && stdout.contains(&format!("{WITNESS}: {instance}")),
        "cold bootstrap process did not complete its real peer and native drain assertions: {stdout}\n{stderr}",
    );
}

fn migrate_here(instance: &'static str, directory: &Path) {
    let directory = directory.to_owned();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("dedicated cold migration runtime");
        runtime.block_on(async {
            let mut agent = super::Agent::start(200, super::ANSWER).await;
            let served = super::served_core_on(
                instance,
                &agent.entry("bootstrap", "1h"),
                Default::default(),
                None,
                None,
                None,
                None,
                super::Facing::Routes,
                None,
                false,
                None,
                &directory,
                true,
            );
            super::approve(&served, "bootstrap").await;
            let (status, body) = super::answered(
                &served.router,
                super::rpc(
                    "bootstrap",
                    "message/send",
                    super::SEND,
                    Some(&served.token),
                ),
            )
            .await;
            assert_eq!(
                status,
                axum::http::StatusCode::OK,
                "real cold migration relay: {body}"
            );
            assert!(
                body.contains("m-far"),
                "actual peer terminal message: {body}"
            );
            assert!(agent.relayed(), "migration reached the actual peer");
            served
                .gov
                .delete_key(&served.key.id)
                .await
                .expect("retire the actual migration caller");
            let kernel = served.kernel.clone();
            assert!(
                tokio::task::spawn_blocking(move || kernel.drain(Duration::from_secs(10)))
                    .await
                    .unwrap(),
                "migration backend work settles before ordinary reopen"
            );
        });
        // Includes the production flush task: no old host can write after ordinary reopen.
        runtime.shutdown_timeout(Duration::from_secs(10));
    })
    .join()
    .expect("cold migration finishes before ordinary serving begins");
}

const SCENARIO: &str = "BUSBAR_A2A_PROCESS_SCENARIO";
const RESPONSES: &str = "BUSBAR_A2A_PUBLIC_RESPONSES";
const SCENARIO_WITNESS: &str = "A2A process scenario finished";

/// Each independent application gets its own process and its one price owner.
/// The parent still requires every exact case's real test and completion witness.
pub(super) async fn scenario(name: &str, responses: Option<&Path>) -> bool {
    if let Ok(selected) = std::env::var(SCENARIO) {
        return selected == name;
    }
    let test = std::thread::current()
        .name()
        .expect("the scenario is driven by a named test")
        .to_owned();
    let mut command =
        tokio::process::Command::new(std::env::current_exe().expect("the actual test binary"));
    command
        .args(["--exact", &test, "--nocapture", "--test-threads=1"])
        .env(SCENARIO, name)
        .kill_on_drop(true);
    if let Some(directory) = responses {
        command.env(RESPONSES, directory);
    }
    let output = command
        .output()
        .await
        .expect("start the exact application scenario");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success()
            && stdout.contains("test result: ok. 1 passed; 0 failed;")
            && stdout.contains(&format!("{SCENARIO_WITNESS}: {test}: {name}")),
        "the independent application scenario did not complete exactly one test: {stdout}\n{stderr}",
    );
    false
}

pub(super) fn scenario_finished(name: &str) {
    assert_eq!(std::env::var(SCENARIO).as_deref(), Ok(name));
    let test = std::thread::current().name().unwrap().to_owned();
    println!("{SCENARIO_WITNESS}: {test}: {name}");
}

/// Only public status/body responses cross between the two isolated applications.
/// The parent owns this directory and removes it after both children have exited.
pub(super) struct ResponseWitness {
    directory: std::path::PathBuf,
    owned: bool,
}

impl ResponseWitness {
    pub(super) fn new() -> Self {
        match std::env::var_os(RESPONSES) {
            Some(directory) => Self {
                directory: directory.into(),
                owned: false,
            },
            None => Self {
                directory: crate::root::test_plugins::scratch("a2a-public-response-witness"),
                owned: true,
            },
        }
    }

    pub(super) fn directory(&self) -> &Path {
        &self.directory
    }

    pub(super) fn write(&self, responses: &[(axum::http::StatusCode, String)]) {
        let public: Vec<_> = responses
            .iter()
            .map(|(status, body)| (status.as_u16(), body))
            .collect();
        std::fs::write(
            self.directory.join("baseline.json"),
            serde_json::to_vec(&public).expect("serialize the public response witness"),
        )
        .expect("retain the actual first process's public responses");
    }

    pub(super) fn read(&self) -> Vec<(axum::http::StatusCode, String)> {
        let public: Vec<(u16, String)> = serde_json::from_slice(
            &std::fs::read(self.directory.join("baseline.json"))
                .expect("read the completed first process's response witness"),
        )
        .expect("read exact public status/body pairs");
        public
            .into_iter()
            .map(|(status, body)| {
                (
                    axum::http::StatusCode::from_u16(status).expect("the original HTTP status"),
                    body,
                )
            })
            .collect()
    }
}

impl Drop for ResponseWitness {
    fn drop(&mut self) {
        if self.owned {
            std::fs::remove_dir_all(&self.directory)
                .expect("remove the completed process response witness");
        }
    }
}
