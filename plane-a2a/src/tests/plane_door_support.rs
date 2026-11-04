use super::*;

impl BackendIds {
    pub(crate) fn len(&self) -> usize {
        self.0.with(&(), |r| r.map_or(0, |r| r.ids.len()))
    }
}

#[test]
fn listing_preserves_parts_written_while_listing_was_pending() {
    let plane = A2aDoor::default();
    let key = (crate::records::KIND_CARD, "a".to_string());
    plane.record_parts.insert(
        key.clone(),
        HeldParts {
            current: vec!["current".to_string()],
            retired: vec!["retired".to_string()],
            carried: true,
        },
    );
    joined(&plane, crate::records::KIND_CARD, Vec::new());
    plane.record_parts.with(&key, |held| {
        let held = held.unwrap();
        assert_eq!(held.current, ["current"]);
        assert_eq!(held.retired, ["retired"]);
        assert!(held.carried);
    });
}

#[test]
fn backend_ids_reject_oversized_keys_and_zero_capacity() {
    let ids = BackendIds::default();
    assert!(!ids.record(0, "a".into(), "b".into()));
    assert!(!ids.record(1, "a".repeat(MAX_BACKEND_KEY_BYTES + 1), "b".into()));
    assert_eq!(ids.len(), 0);
}

fn unit() -> AgentUnit {
    AgentUnit::new(
        AgentDisposition::Notice {
            method: "notice".into(),
        },
        None,
        None,
        1,
    )
}

#[test]
fn ended_units_release_payloads_and_retain_refusal_shape() {
    let mut unit = unit();
    let request = serde_json::json!({"method":"message/stream","params":{"metadata":{"skill":"plan"},"message":{"parts":[{"text":"secret"}]}}});
    let shape = crate::skill::TaskShape::of(&request);
    let mut hop = Hop::task(serde_json::json!(1), "1.0", request);
    let cfg = agents_section(
        br#"{"planner":{"url":"https://planner.example/a2a","pin":{"mechanism":"unpinned"}}}"#,
    )
    .unwrap();
    hop.verifying = Some(LookParked::Sighted {
        registration: cfg.agents["planner"].clone(),
        generation: 1,
        looked: CardLook {
            sighting: Default::default(),
            card: None,
        },
        issued: 0,
        unreachable: false,
    });
    hop.relay.send_instead(b"secret".to_vec());
    hop.outbox = Outbox::of(PieceAnswer::ToFarEnd(b"secret".to_vec().into())).unwrap();
    unit.hop = Some(hop);
    unit.envelope = Some(zeroize::Zeroizing::new(b"secret".to_vec()));
    unit.end();
    assert!(unit.over);
    assert_eq!(unit.ended_shape, Some(shape));
    assert!(unit.envelope.as_ref().unwrap().is_empty());
    let hop = unit.hop.as_ref().unwrap();
    assert!(hop.request.is_none());
    assert!(hop.verifying.is_none());
    assert!(hop.outbox.bytes.is_empty());
    assert!(hop.relay.replacement_bytes().is_none());
}

#[test]
fn full_units_are_reclaimed_only_after_a_completion() {
    let plane = A2aDoor::default();
    for id in 0..MAX_UNITS as u64 {
        plane.units.insert(id, unit());
    }
    assert!(!room_for(&plane, MAX_UNITS as u64));
    assert!(room_for(&plane, 0));
    plane.on_unit(0, AgentUnit::end);
    plane
        .cleanup_pending
        .store(true, std::sync::atomic::Ordering::Release);
    assert!(room_for(&plane, MAX_UNITS as u64));
    assert!(plane.units.with(&0, |u| u.is_none()));
}

#[test]
fn a_verb_updates_standing_without_resetting_the_verification_ledger() {
    let plane = A2aDoor::default();
    let cfg = agents_section(
        br#"{"planner":{"url":"https://planner.example/a2a","pin":{"mechanism":"unpinned"}}}"#,
    )
    .unwrap();
    let def = cfg.agents["planner"].clone();
    let spec = statement::agents_snapshot_spec(None, &["planner"]);
    let _ = plane.generations.publish_with(1, &spec, cfg);
    PlaneLife::published(&plane, 1);
    let mut standing = crate::card_trust::TrustStanding::default();
    standing.ledger.last_checked_ms = Some(123);
    plane.trust.insert("planner".into(), standing);
    assert!(kept_standing(&plane, ("planner", &def), &Default::default(), None).is_some());
    assert_eq!(
        plane
            .trust
            .get(&"planner".into())
            .unwrap()
            .ledger
            .last_checked_ms,
        Some(123)
    );
}

#[test]
fn a_clock_failure_retains_pending_task_settlements() {
    let plane = A2aDoor::default();
    let mut hop = Hop::task(serde_json::json!(1), "1.0", serde_json::json!({}));
    // A task is required before settlement reaches the host clock.
    hop.relay.for_task(crate::relay::TaskHop {
        task_id: "task".into(),
        context_id: "context".into(),
        skill: None,
        addressed: false,
        references: Vec::new(),
    });
    hop.settle.push(TaskSettled::Failed);
    let reach = Reach {
        plane: &plane,
        ticket: Ticket::NONE,
    };
    let result = settle_task(&reach, &mut hop, &mut Default::default(), "caller");
    assert_eq!(result, Err(Outcome::Failed));
    assert_eq!(hop.settle.len(), 1);
}

#[test]
fn an_unavailable_entitlement_service_is_retryable_not_a_denial() {
    let plane = A2aDoor::default();
    let reach = Reach {
        plane: &plane,
        ticket: Ticket::NONE,
    };
    let refused =
        caller_stands(&reach, &mut Default::default(), "planner", Some("planner")).unwrap();
    assert_eq!(refused.status, 503);
    assert!(refused.message.contains("entitlement service"));
}

#[test]
fn backend_ids_evict_to_the_aggregate_byte_budget() {
    let ids = BackendIds::default();
    for i in 0..2000 {
        let key = format!("{i:04}{}", "x".repeat(MAX_BACKEND_KEY_BYTES - 4));
        assert!(ids.record(MAX_BACKEND_IDS, key, "id".into()));
    }
    assert!(ids.len() < 2000);
    ids.0
        .with(&(), |r| assert!(r.unwrap().bytes <= MAX_BACKEND_BYTES));
}

#[test]
fn a_missing_clock_fails_verification_without_a_false_demotion() {
    let plane = A2aDoor::default();
    let cfg = agents_section(
        br#"{"planner":{"url":"https://planner.example/a2a","pin":{"mechanism":"unpinned"}}}"#,
    )
    .unwrap();
    let mut hop = Hop::new(serde_json::json!(1), "1.0");
    let reach = Reach {
        plane: &plane,
        ticket: Ticket::NONE,
    };
    assert_eq!(
        verify_agent_on_call(
            &reach,
            &mut hop,
            &mut Default::default(),
            "planner",
            &cfg.agents["planner"],
            1
        ),
        Poll::Ready(Err(Outcome::Failed))
    );
}

#[test]
fn a_flight_acquired_after_another_look_lands_reuses_the_new_ledger() {
    let plane = A2aDoor::default();
    let cadence = crate::card_trust::Cadence { ttl_ms: 1000 };
    let stale = crate::card_trust::TrustStanding::default();
    assert!(cadence.due(&stale.ledger, 200));
    let mut fresh = stale;
    fresh.ledger.last_checked_ms = Some(199);
    plane.trust.insert("planner".into(), fresh);
    assert_eq!(plane.flights.join("planner", Ticket::NONE), None);
    assert!(reuse_fresh_look(&plane, "planner", cadence, 200).is_some());
    assert_eq!(
        plane.flights.join(
            "planner",
            Ticket {
                slot: 2,
                generation: 1
            }
        ),
        None
    );
}
