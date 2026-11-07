// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::conn::{ConnError, OpenDesc, PieceKind, PollConns};
use busbar_kernel::plane_driver::Egress;
use std::time::Duration;

fn current_egress(s: &Served) -> (u64, Arc<Egress>) {
    assert_eq!(
        s.appliers.0.len(),
        1,
        "this fixture opens one actual A2A plane"
    );
    let live = s.appliers.0[0].current();
    (
        live.generation,
        live.egress
            .as_ref()
            .expect("the actual route is sealed")
            .clone(),
    )
}

async fn apply_agent(s: &Served, agent: &Agent, previous: u64) -> Arc<Egress> {
    let next = s.applied(
        serde_yaml::from_str(&agent.entry("planner", "1h")).expect("the real agent section"),
        false,
    );
    s.handle.swap(next).await;
    let (generation, egress) = current_egress(s);
    assert_eq!(
        generation,
        previous + 1,
        "actual REFRESH published its next generation"
    );
    egress
}

// Cross the real connection table, consume the HTTP response, and close every connection.
// This deliberately does not keep a loader ticket or an EgressFarEnd alive between checks.
async fn fetch(
    conns: &dyn PollConns,
    owner: busbar_contract::conn::InstanceId,
    need: busbar_contract::conn::NeedId,
    target: &str,
) -> Result<Vec<u8>, ConnError> {
    let body = br#"{"jsonrpc":"2.0","id":1,"method":"message/send","params":{}}"#;
    // The actual HTTP framer owns content-length and transfer-encoding.
    let fields: &[(&str, &[u8])] = &[("content-type", b"application/json")];
    let conn = conns.open_with_security(
        owner,
        need,
        &OpenDesc {
            target,
            fields,
            body: body.to_vec().into(),
            timeout_ms: 2_000,
            method: b"POST",
            head_target: b"/planner",
            member: "planner",
            ..OpenDesc::default()
        },
        false,
    )?;
    let result = tokio::time::timeout(Duration::from_secs(3), async {
        let mut answer = Vec::new();
        let mut status = None;
        loop {
            let mut bytes = [0; 4096];
            let piece =
                std::future::poll_fn(|cx| conns.poll_read(owner, conn, cx, &mut bytes)).await?;
            if let Some(code) = piece.status_code {
                status = Some(code);
            }
            if piece.kind == PieceKind::Body {
                answer.extend_from_slice(&bytes[..piece.len]);
                if piece.end {
                    break;
                }
            } else if piece.kind == PieceKind::Completion {
                break;
            }
        }
        assert_eq!(status, Some(200), "the real far agent answered the request");
        assert!(String::from_utf8_lossy(&answer).contains("m-far"));
        Ok(answer)
    })
    .await
    .unwrap_or(Err(ConnError::Timeout));
    let closed = conns.close(owner, conn);
    if result.is_ok() {
        assert_eq!(closed, Ok(()), "the completed real connection is released");
    }
    result
}

fn route(egress: &Egress) -> (busbar_contract::conn::NeedId, String) {
    assert_eq!(egress.routes.len(), 1, "one actual agent route");
    let route = egress.routes.values().next().unwrap();
    assert_eq!(route.provider, "planner");
    (route.need, route.base_url.clone())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_retained_egress_keeps_its_connection_authority_across_two_later_refreshes() {
    let _one = PUBLISHING.lock().await;
    // Four live peers avoid conflating authority retirement with a disappearing listener.
    let initial = Agent::start(200, ANSWER).await;
    let first = Agent::start(200, ANSWER).await;
    let second = Agent::start(200, ANSWER).await;
    let third = Agent::start(200, ANSWER).await;
    let s = served(
        "binding-authority-lifetime",
        &initial.entry("planner", "1h"),
        false,
        None,
    );
    let (initial_generation, initial_egress) = current_egress(&s);
    let initial_owner = initial_egress.caller;
    drop(initial_egress);

    // OPEN's generation is rooted by the loader. Capture a noninitial generation,
    // so releasing this Egress must actually revoke its connection authority.
    let retained = apply_agent(&s, &first, initial_generation).await;
    let (first_generation, _) = current_egress(&s);
    let old_owner = retained.caller;
    assert_ne!(old_owner, initial_owner);
    let (old_need, old_target) = route(&retained);
    fetch(&*retained.conns, old_owner, old_need, &old_target)
        .await
        .unwrap();

    let middle = apply_agent(&s, &second, first_generation).await;
    let (second_generation, _) = current_egress(&s);
    assert_ne!(middle.caller, old_owner);
    let (middle_need, middle_target) = route(&middle);
    fetch(&*middle.conns, middle.caller, middle_need, &middle_target)
        .await
        .unwrap();
    assert_eq!(
        fetch(&*retained.conns, old_owner, old_need, &middle_target).await,
        Err(ConnError::Refused),
        "the retained generation cannot acquire the replacement target"
    );
    drop(middle);

    let current = apply_agent(&s, &third, second_generation).await;
    assert_ne!(current.caller, old_owner);
    let (new_need, new_target) = route(&current);
    fetch(&*current.conns, current.caller, new_need, &new_target)
        .await
        .unwrap();
    assert_eq!(
        fetch(&*current.conns, current.caller, new_need, &old_target).await,
        Err(ConnError::Refused),
        "the current generation cannot acquire the removed old target"
    );
    // No DoorLive, ticket or open connection keeps the old generation: only this
    // retained Arc<Egress> does. Its original authority still reaches its own peer.
    fetch(&*retained.conns, old_owner, old_need, &old_target)
        .await
        .unwrap();

    let raw = Arc::clone(&s.riding.inner);
    drop(retained);
    assert_eq!(
        fetch(&*raw, old_owner, old_need, &old_target).await,
        Err(ConnError::UndeclaredNeed),
        "releasing the last retained Egress revokes the noninitial authority"
    );
    // Revocation was specific to the released generation, not to its shared table.
    fetch(&*current.conns, current.caller, new_need, &new_target)
        .await
        .unwrap();
}
