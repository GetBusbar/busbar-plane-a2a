// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
use super::*;

#[test]
fn client_identity_files_are_unique_for_repeated_names() {
    rig::install_crypto_provider();
    let first = client_identity_files("repeated-identity-fixture", "planner");
    let cert = std::fs::read(&first.1).unwrap();
    let key = std::fs::read(&first.2).unwrap();
    let second = client_identity_files("repeated-identity-fixture", "planner");

    struct Cleanup(Vec<String>);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            for path in &self.0 {
                let _ = std::fs::remove_file(path);
            }
        }
    }
    let _cleanup = Cleanup(vec![
        first.1.clone(),
        first.2.clone(),
        second.1.clone(),
        second.2.clone(),
    ]);
    assert_ne!(first.1, second.1);
    assert_ne!(first.2, second.2);
    assert_eq!(std::fs::read(&first.1).unwrap(), cert);
    assert_eq!(std::fs::read(&first.2).unwrap(), key);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn accepted_socket_counter_observes_non_http_traffic_before_parsing() {
    use tokio::io::AsyncWriteExt as _;
    let agent = Agent::start(200, ANSWER).await;
    assert_eq!(agent.accepted(), 0);
    let mut socket = tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, agent.port))
        .await
        .unwrap();

    socket
        .write_all(&[0x16, 0x03, 0x03, 0x00, 0x01, 0x00])
        .await
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while agent.accepted() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the listener observes the accepted socket");
    assert_eq!(agent.accepted(), 1);
    assert_eq!(agent.fetches(), 0, "no HTTP card fetch was decoded");
    socket.shutdown().await.unwrap();
}

#[test]
fn client_identity_files_are_removed_when_the_owner_is_dropped() {
    rig::install_crypto_provider();
    let files = client_identity_files("identity-drop-fixture", "planner");
    let cert = files.1.clone();
    let key = files.2.clone();
    assert!(std::path::Path::new(&cert).exists());
    assert!(std::path::Path::new(&key).exists());
    drop(files);
    assert!(!std::path::Path::new(&cert).exists());
    assert!(!std::path::Path::new(&key).exists());
}
