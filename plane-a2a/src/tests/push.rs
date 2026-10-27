// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Push delivery in plane memory: the retry schedule and what it retries, the per-task order, the
//! bounded queue and its count, the credential's path, and busbar's own callback tokens.

use super::*;

/// What a test reads off the delivery queues.
impl Deliveries {
    /// How many notifications were dropped from full queues.
    #[must_use]
    pub(crate) fn dropped(&self) -> u64 {
        self.with(|b| b.dropped)
    }

    /// How many notifications `task_id`'s queue holds.
    #[must_use]
    pub(crate) fn depth(&self, task_id: &str) -> usize {
        self.with(|b| b.queues.get(task_id).map_or(0, VecDeque::len))
    }

    /// The deliveries to attempt now: each task's head, when its time has come and no attempt on
    /// it is open. Each is marked open until [`Deliveries::settle`].
    #[must_use]
    pub(crate) fn due(&self, now_ns: u64) -> Vec<Delivery> {
        self.with(|b| {
            b.queues
                .values_mut()
                .filter_map(VecDeque::front_mut)
                .filter(|w| !w.open && w.not_before_ns <= now_ns)
                .map(|w| {
                    w.open = true;
                    w.attempts += 1;
                    w.delivery.clone()
                })
                .collect()
        })
    }

    /// How many owed outcomes were dropped unfiled from a full book.
    #[must_use]
    pub(crate) fn unfiled(&self) -> u64 {
        self.with(|b| b.unfiled)
    }
}
use crate::a2a::task::{Direction, TaskState};
use busbar_contract::abi::host::service::DEST_METADATA;
use busbar_contract::abi::sdk::exchange::Exchange;
use busbar_contract::abi::sdk::test_support::chip::{cred, framed_head, sealed_bytes};

const MS: u64 = 1_000_000;

/// A task named `id` with a callback, in `state`.
fn task(id: &str, state: TaskState) -> Task {
    let mut t = Task::submitted(id, "ctx", "principal", Direction::Inbound, 0).expect("a task");
    t.push_callback = Some(format!("https://hook.example/cb/{id}?k=v"));
    if state != TaskState::Submitted {
        t.transition_to(TaskState::Working, 1).expect("working");
    }
    if state != TaskState::Working && state != TaskState::Submitted {
        t.transition_to(state, 2).expect("the state");
    }
    t
}

fn delivery(id: &str) -> Delivery {
    Delivery::of(&task(id, TaskState::Working)).expect("a callback")
}

#[test]
fn only_a_transport_error_a_5xx_or_a_429_is_retried() {
    for end in [
        Attempted::Transport,
        Attempted::Status(429),
        Attempted::Status(500),
        Attempted::Status(503),
        Attempted::Status(599),
    ] {
        assert!(end.retryable(), "{end:?}");
    }
    for end in [
        Attempted::Delivered,
        Attempted::Judged(DEST_METADATA),
        Attempted::Status(400),
        Attempted::Status(404),
        Attempted::Status(428),
        Attempted::Status(600),
        Attempted::Status(302),
    ] {
        assert!(!end.retryable(), "{end:?}");
    }
    assert_eq!(Attempted::of_status(204), Attempted::Delivered);
    assert_eq!(Attempted::of_status(300), Attempted::Status(300));
    assert_eq!(Attempted::of_status(199), Attempted::Status(199));
}

#[test]
fn the_wait_is_the_base_moved_by_at_most_twenty_percent() {
    assert_eq!((jittered_ms(250, 0), jittered_ms(250, 255)), (200, 300));
    assert_eq!((jittered_ms(500, 0), jittered_ms(500, 255)), (400, 600));
    for byte in 0..=u8::MAX {
        let w = jittered_ms(250, byte);
        assert!((200..=300).contains(&w), "{byte}: {w}");
    }
}

#[test]
fn a_failing_receiver_gets_three_attempts_at_250_then_500_ms_and_no_fourth() {
    let d = Deliveries::default();
    d.enqueue(delivery("t1"), 0);
    assert_eq!(d.due(0).len(), 1);
    // The low end of the first wait (250 - 20 %), then the high end of the second (500 + 20 %).
    assert_eq!(
        d.settle("t1", Attempted::Status(503), 0, 0),
        DeliverySettled::Retry(200 * MS)
    );
    assert!(d.due(199 * MS).is_empty(), "nothing before its time");
    assert_eq!(d.next_tick_ns(), 200 * MS);
    assert_eq!(d.due(200 * MS).len(), 1);
    assert_eq!(
        d.settle("t1", Attempted::Transport, 200 * MS, 255),
        DeliverySettled::Retry(800 * MS)
    );
    assert_eq!(d.due(800 * MS).len(), 1);
    assert_eq!(
        d.settle("t1", Attempted::Status(429), 800 * MS, 0),
        DeliverySettled::Done(vocab::EV_PUSH_FAILED)
    );
    assert!(d.due(u64::MAX).is_empty(), "no fourth attempt");
    assert_eq!((d.depth("t1"), d.next_tick_ns()), (0, 0));
}

#[test]
fn a_refused_destination_or_a_4xx_ends_the_delivery_at_once() {
    let d = Deliveries::default();
    d.enqueue(delivery("a"), 0);
    d.enqueue(delivery("b"), 0);
    d.enqueue(delivery("c"), 0);
    assert_eq!(d.due(0).len(), 3);
    assert_eq!(
        d.settle("a", Attempted::Judged(DEST_METADATA), 0, 0),
        DeliverySettled::Done(vocab::EV_PUSH_REFUSED)
    );
    assert_eq!(
        d.settle("b", Attempted::Status(404), 0, 0),
        DeliverySettled::Done(vocab::EV_PUSH_FAILED)
    );
    assert_eq!(
        d.settle("c", Attempted::Delivered, 0, 0),
        DeliverySettled::Done(vocab::EV_PUSH_DELIVERED)
    );
    assert_eq!(
        d.settle("c", Attempted::Delivered, 0, 0),
        DeliverySettled::Unknown
    );
    assert_eq!(d.next_tick_ns(), 0);
}

#[test]
fn a_tasks_notifications_go_out_in_order_one_at_a_time() {
    let d = Deliveries::default();
    let mut first = delivery("t1");
    first.body = b"first".to_vec();
    let mut second = delivery("t1");
    second.body = b"second".to_vec();
    d.enqueue(first, 0);
    d.enqueue(second, 0);
    d.enqueue(delivery("t2"), 0);
    let due = d.due(0);
    let bodies: Vec<&[u8]> = due
        .iter()
        .filter(|x| x.task_id == "t1")
        .map(|x| x.body.as_slice())
        .collect();
    assert_eq!(bodies, [b"first".as_slice()]);
    assert_eq!(due.len(), 2, "t2 does not wait on t1");
    assert!(
        d.due(0).is_empty(),
        "an open attempt is not handed out twice"
    );
    assert_eq!(
        d.next_tick_ns(),
        0,
        "no tick is wanted while every head is open"
    );
    // A retry holds the task's later notifications behind it.
    d.settle("t1", Attempted::Status(500), 0, 0);
    assert!(d.due(199 * MS).is_empty());
    assert_eq!(d.due(200 * MS)[0].body, b"first");
    d.settle("t1", Attempted::Delivered, 200 * MS, 0);
    assert_eq!(d.due(200 * MS)[0].body, b"second");
}

#[test]
fn a_full_queue_drops_its_oldest_waiting_notification_and_counts_it() {
    let d = Deliveries::default();
    for i in 0..QUEUE_CAPACITY {
        let mut x = delivery("t1");
        x.body = i.to_string().into_bytes();
        assert!(!d.enqueue(x, 0));
    }
    assert_eq!((d.depth("t1"), d.dropped()), (QUEUE_CAPACITY, 0));
    let mut newest = delivery("t1");
    newest.body = b"newest".to_vec();
    assert!(d.enqueue(newest, 0));
    assert_eq!((d.depth("t1"), d.dropped()), (QUEUE_CAPACITY, 1));
    assert_eq!(d.due(0)[0].body, b"1", "the oldest was the one dropped");
    // The head is now open: the next drop takes the oldest WAITING one, never the attempt.
    assert!(d.enqueue(delivery("t1"), 0));
    assert_eq!(d.dropped(), 2);
    assert_eq!(
        d.take_counted(),
        (2, 0),
        "the drops are reported as a counter's increment"
    );
    assert_eq!(d.take_counted(), (0, 0), "and each drop once");
    assert_eq!(
        d.settle("t1", Attempted::Delivered, 0, 0),
        DeliverySettled::Done(vocab::EV_PUSH_DELIVERED)
    );
    assert_eq!(d.due(0)[0].body, b"3");
}

/// THE REQUEST AS IT WAS BEFORE THE CHIP (plane-a2a dev at 28bd001, `push::request` and
/// `DeliveryAuth::header_value`), kept verbatim as the oracle the sealed request is held to.
fn legacy_request(delivery: &Delivery, auth: Option<(&str, &str)>) -> Request {
    let target = url::Url::parse(&delivery.url).map_or_else(
        |_| "/".to_string(),
        |u| match u.query() {
            Some(q) => format!("{}?{q}", u.path()),
            None => u.path().to_string(),
        },
    );
    let mut fields = vec![(
        CONTENT_TYPE.0.as_bytes().to_vec(),
        CONTENT_TYPE.1.as_bytes().to_vec(),
    )];
    if let Some((scheme, credentials)) = auth {
        let header_value = if credentials.is_empty() {
            scheme.to_string()
        } else {
            format!("{scheme} {credentials}")
        };
        fields.push((AUTHORIZATION.as_bytes().to_vec(), header_value.into_bytes()));
    }
    Request {
        method: b"POST".to_vec(),
        target: target.into_bytes(),
        fields,
        body: delivery.body.clone(),
        timeout_ms: ATTEMPT_TIMEOUT_MS,
    }
}

/// The whole head the delivery's exchange frames, sealed values included.
fn framed(d: &Deliveries, x: &Delivery) -> Vec<u8> {
    let (request, sealed) = d.request(x);
    framed_head(&Exchange::request_sealed(request, sealed).expect("the request frames"))
}

fn auth(scheme: &str, credentials: &str) -> DeliveryAuth {
    DeliveryAuth {
        scheme: scheme.into(),
        credentials: cred(credentials),
    }
}

#[test]
fn the_request_is_a_post_to_the_callbacks_path_with_the_credential_only_once_held() {
    let d = Deliveries::default();
    let x = delivery("t1");
    let (bare, sealed) = d.request(&x);
    assert_eq!(bare.method, b"POST");
    assert_eq!(bare.target, b"/cb/t1?k=v");
    assert_eq!(
        bare.fields,
        [(b"content-type".to_vec(), b"application/json".to_vec())]
    );
    assert_eq!(bare.body, x.body);
    assert!(sealed.is_empty());
    d.remember_auth("t1", Some(auth("Bearer", "s3cret")));
    let (with, sealed) = d.request(&x);
    assert_eq!(with.fields.len(), 1, "the credential is no plain field");
    assert_eq!(sealed.len(), 1);
    assert_eq!((sealed[0].0, &sealed[0].1[..]), (1, &b"authorization"[..]));
    assert_eq!(sealed_bytes(&sealed[0].2), b"Bearer s3cret");
    d.remember_auth("t1", None);
    assert!(
        d.request(&x).1.is_empty(),
        "a withdrawn credential is not sent"
    );
}

/// THE WIRE IS THE ONE THE PLANE SENT BEFORE THE CHIP: for every shape of credential a caller
/// registers (a scheme and a credential, a bare scheme, a credential with inner spaces, none), and
/// a callback with and without a query, the sealed request frames exactly the head the plain
/// request framed: the field order, the separator, every byte. RED against a sealed field placed
/// anywhere but after the content type, or a recipe that writes the scheme its own way.
#[test]
fn the_sealed_request_frames_the_bytes_the_plain_one_did() {
    let shapes: [Option<(&str, &str)>; 5] = [
        None,
        Some(("Bearer", "s3cret")),
        Some(("Basic", "")),
        Some(("Token", "a b  c")),
        Some(("bEaReR", "x.y-z_~+/=")),
    ];
    for url in [
        "https://hook.example/cb/t1?k=v",
        "https://hook.example/",
        "https://hook.example/a/b",
    ] {
        for shape in shapes {
            let d = Deliveries::default();
            let x = Delivery {
                url: url.to_string(),
                ..delivery("t1")
            };
            d.remember_auth("t1", shape.map(|(s, c)| auth(s, c)));
            let old = Exchange::request(legacy_request(&x, shape)).expect("frames");
            assert_eq!(
                framed(&d, &x),
                framed_head(&old),
                "{url} {:?}",
                shape.map(|(s, _)| s)
            );
            let (request, _) = d.request(&x);
            let legacy = legacy_request(&x, shape);
            assert_eq!(request.body, legacy.body);
            assert_eq!(request.timeout_ms, legacy.timeout_ms);
        }
    }
}

/// An `https` callback's credential goes out only on a secured stream.
#[test]
fn the_sealed_credential_requires_the_secured_stream_its_https_callback_names() {
    let a = auth("Bearer", "s3cret");
    assert!(a.authorization("https://hook.example/cb").secure_required());
}

#[test]
fn a_terminal_tasks_last_delivery_forgets_its_credential() {
    let d = Deliveries::default();
    d.remember_auth("t1", Some(auth("Basic", "")));
    let last = Delivery::of(&task("t1", TaskState::Completed)).expect("a callback");
    assert!(last.terminal);
    d.enqueue(last.clone(), 0);
    assert_eq!(sealed_bytes(&d.request(&last).1[0].2), b"Basic");
    let _ = d.due(0);
    d.settle("t1", Attempted::Delivered, 0, 0);
    assert!(d.request(&last).1.is_empty());
}

#[test]
fn the_credential_never_prints() {
    let a = auth("Bearer", "s3cret");
    assert!(!format!("{a:?}").contains("s3cret"));
    assert_eq!(
        sealed_bytes(&a.authorization("https://hook.example/")),
        b"Bearer s3cret"
    );
}

#[test]
fn the_notification_is_the_task_nested_under_task_with_an_rfc3339_timestamp() {
    let t = task("t1", TaskState::Completed);
    let body: serde_json::Value = serde_json::from_slice(&notification_body(&t)).expect("JSON");
    assert_eq!(
        body,
        serde_json::json!({"task": {"id": "t1", "contextId": "ctx",
            "status": {"state": "TASK_STATE_COMPLETED", "timestamp": "1970-01-01T00:00:02Z"}}})
    );
    assert!(body.get("jsonrpc").is_none());
    let mut silent = t;
    silent.push_callback = None;
    assert_eq!(
        Delivery::of(&silent),
        None,
        "no callback, nothing to deliver"
    );
}

/// THE NOTIFICATION TAKES THE SHAPE OF THE VERSION ITS CALLBACK WAS REGISTERED UNDER (Q128 a2a M13,
/// ruled version-consistent). v1.0: a `StreamResponse` carrying the task, its state a ProtoJSON
/// `TASK_STATE_*` token and no `kind`. v0.3: the `Task` object itself, `kind: "task"` and the
/// lower-case state word. RED before the fix: one mixed body, the v1.0 wrapper around v0.3 words.
#[test]
fn the_notification_is_the_registered_versions_shape() {
    let mut t = task("t1", TaskState::Completed);
    t.push_version = "1.0".into();
    let v10: serde_json::Value = serde_json::from_slice(&notification_body(&t)).expect("JSON");
    assert_eq!(
        v10,
        serde_json::json!({"task": {"id": "t1", "contextId": "ctx",
            "status": {"state": "TASK_STATE_COMPLETED", "timestamp": "1970-01-01T00:00:02Z"}}})
    );
    t.push_version = "0.3".into();
    let v03: serde_json::Value = serde_json::from_slice(&notification_body(&t)).expect("JSON");
    assert_eq!(
        v03,
        serde_json::json!({"id": "t1", "contextId": "ctx", "kind": "task",
            "status": {"state": "completed", "timestamp": "1970-01-01T00:00:02Z"}})
    );
    // A row written before the version was kept reads as v1.0.
    t.push_version = String::new();
    let old: serde_json::Value = serde_json::from_slice(&notification_body(&t)).expect("JSON");
    assert_eq!(old, v10);
}

#[test]
fn a_callback_token_names_its_one_task_and_nothing_else() {
    let tokens = Tokens::default();
    let sig_a = [7u8; 64];
    let token = tokens.mint("c1", "task.a", &sig_a).expect("minted");
    assert_eq!(token, format!("task.a.{}", hex(&sig_a)));
    let (task, caller, presented) = tokens.claim(&token).expect("claimed");
    assert_eq!((task.as_str(), caller.as_str()), ("task.a", "c1"));
    assert!(verified(&sig_a, presented));
    assert!(
        !verified(&[8u8; 64], presented),
        "another signature is refused"
    );
    let other = tokens.mint("c2", "task.b", &[8u8; 64]).expect("minted");
    let (_, b_sig) = other.rsplit_once('.').expect("a token");
    let forged_token = format!("task.a.{b_sig}");
    let (_, _, forged) = tokens.claim(&forged_token).expect("a claim on a held task");
    assert!(
        !verified(&sig_a, forged),
        "task b's signature names task a for nothing"
    );
    for refused in [
        "task.a".to_string(),
        "task.a.".to_string(),
        format!("task.c.{b_sig}"),
        String::new(),
        ".".to_string(),
    ] {
        assert_eq!(tokens.claim(&refused), None, "{refused}");
    }
    assert!(tokens
        .claim_of_authorization(&format!("bearer {token}"))
        .is_some());
    assert!(tokens
        .claim_of_authorization(&format!("Basic {token}"))
        .is_none());
    tokens.forget("task.a");
    assert_eq!(tokens.claim(&token), None, "a forgotten token is refused");
    assert_eq!(tokens.mint("c", "t", &[]), None);
    assert_eq!(tokens.mint("c", "", &sig_a), None);
    assert_eq!(token_input("t"), b"busbar-a2a-push-token\0t".to_vec());
}

#[test]
fn tokens_are_bounded() {
    let tokens = Tokens::default();
    let sig = [3u8; 64];
    for i in 0..MAX_TOKENS {
        assert!(tokens.mint("c", &i.to_string(), &sig).is_some());
    }
    assert_eq!(tokens.mint("c", "one-more", &sig), None);
    assert!(
        tokens.mint("c", "0", &sig).is_some(),
        "a held one is still answered"
    );
}

/// 1.5.5's push-volume bound: 60 per task per fixed 60 s window, other tasks untouched, a fresh
/// window refills, and a clock that steps back cannot reopen a spent window.
#[test]
fn the_push_volume_bound_is_one_point_five_point_fives() {
    let limiter = PushLimiter::default();
    for _ in 0..PUSH_RATE_LIMIT {
        assert!(limiter.admit("t", 120));
    }
    assert!(!limiter.admit("t", 179), "the window's budget is spent");
    assert!(limiter.admit("u", 179), "another task has its own budget");
    assert!(limiter.admit("t", 180), "the next window refills");
    for _ in 1..PUSH_RATE_LIMIT {
        assert!(limiter.admit("t", 181));
    }
    assert!(
        !limiter.admit("t", 60),
        "a regressed clock judges the newest window"
    );
}

#[test]
fn the_statement_declares_its_open_web_need_and_its_agent_member_need() {
    use crate::door_statement::{MEMBER_TARGET, NEEDS, NEED_AGENT, NEED_OPEN_WEB};
    use busbar_contract::abi::host::conn::connector::{
        DIRECTION_OUTBOUND, EGRESS_OPEN_WEB, EGRESS_PROVIDER,
    };
    use busbar_contract::abi::mechanism::check::check_needs;
    let st = &crate::agent_door::STATEMENT;
    assert!(!st.needs_ptr().is_null());
    // The open web, the agents over http, the agents over grpc.
    assert_eq!((st.needs_len(), NEEDS.len()), (3, 3));
    // The relayed calls' need: each registered agent reached at its own `url`, as an upstream.
    let agent = NEEDS[NEED_AGENT as usize];
    assert_eq!(
        (agent.direction, agent.egress_class),
        (DIRECTION_OUTBOUND, EGRESS_PROVIDER)
    );
    assert_eq!(
        agent.target_from.len(),
        MEMBER_TARGET.len(),
        "settings.*.url"
    );
    assert!(check_needs(NEEDS).is_ok());
    let need = NEEDS[NEED_OPEN_WEB as usize];
    assert_eq!(
        (need.direction, need.egress_class),
        (DIRECTION_OUTBOUND, EGRESS_OPEN_WEB)
    );
    assert_eq!(
        need.transport.len(),
        crate::claims::DOCUMENT_TRANSPORT.len(),
        "the http claim"
    );
    assert_eq!(
        (need.auth.len(), need.target_from.len()),
        (0, 0),
        "no auth style, no configured target: the plane names each dial's target"
    );
    assert_eq!(
        need.trust_from.len(),
        crate::door_statement::PUSH_TRUST_FROM.len(),
        "its trust anchor is the operator's optional `agent_push.ca` (the text is pinned by the \
         conformance read of the rendered Statement)"
    );
}

/// THE PUSH NEED'S TRUST IS THE PLANE'S OWN `agent_push.ca`, in the owned namespace (ARCHITECT ruling
/// 2026-10-14): the path names the section the Statement owns beside `agents:` and its one key, and
/// the section is stated as the plane's own (not declaring, not consumed).
#[test]
fn the_push_trust_path_names_the_owned_agent_push_section() {
    use crate::door_statement::{PUSH_CA_KEY, PUSH_SECTION, PUSH_TRUST_FROM, SECTIONS};
    use busbar_contract::section::{owned_path, OWNED_PATH_PREFIX};
    assert_eq!(
        PUSH_TRUST_FROM,
        format!("{OWNED_PATH_PREFIX}{PUSH_SECTION}.{PUSH_CA_KEY}")
    );
    assert_eq!(
        owned_path(PUSH_TRUST_FROM),
        Some(format!("{PUSH_SECTION}.{PUSH_CA_KEY}").as_str())
    );
    assert_eq!(SECTIONS.len(), 2, "`agents:`, and `agent_push:` beside it");
    assert_eq!(
        (SECTIONS[1].name.len(), SECTIONS[1].flags),
        (PUSH_SECTION.len(), 0),
        "owned, as written: neither declaring nor consumed"
    );
}

/// THE `agent_push:` SECTION'S SHAPE, as the plane judges it at `open` and `refresh`: absent (or
/// null) is off; present, a mapping holding `ca` alone, non-empty text. Whether the text is a
/// usable trust anchor is the host's to judge.
#[test]
fn the_agent_push_section_holds_its_ca_alone() {
    use crate::door_statement::read_push_section;
    for fine in [
        &b""[..],
        br#"{}"#,
        br#"{"agent_push":null}"#,
        br#"{"agent_push":{}}"#,
        br#"{"agent_push":{"ca":"-----BEGIN CERTIFICATE-----"}}"#,
        br#"{"other":{"x":1}}"#,
    ] {
        assert_eq!(
            read_push_section(fine),
            Ok(()),
            "{}",
            String::from_utf8_lossy(fine)
        );
    }
    for (bad, says) in [
        (&br#"{"agent_push":"pem"}"#[..], "must be a mapping"),
        (br#"{"agent_push":{"ca":""}}"#, "PEM text"),
        (br#"{"agent_push":{"ca":7}}"#, "PEM text"),
        (br#"{"agent_push":{"cert":"pem"}}"#, "`agent_push.cert`"),
    ] {
        let err = read_push_section(bad).expect_err("refused");
        assert!(err.contains(says), "{err}");
    }
}

/// predev's token: `<task-id>.` then `hex::encode` of an HMAC-SHA256, 64 lower-case hex digits.
fn predev_shaped(token: &str, task_id: &str) -> bool {
    token
        .strip_prefix(task_id)
        .and_then(|t| t.strip_prefix('.'))
        .is_some_and(|mac| {
            mac.len() == 64
                && mac
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
}

#[test]
fn a_callback_token_has_predevs_wire_shape_and_rides_its_bearer_scheme() {
    let tokens = Tokens::default();
    // predev's own HMAC token for task `t-1` (hex of a 32-byte MAC) is the shape the check holds.
    let predev = "t-1.5d41402abc4b2a76b9719d911017c5925d41402abc4b2a76b9719d911017c592";
    assert!(predev_shaped(predev, "t-1"));
    for (task, sig) in [("t-1", [0u8; 64]), ("a.b", [0xffu8; 64])] {
        let token = tokens.mint("c", task, &sig).expect("minted");
        assert!(predev_shaped(&token, task), "{token}");
    }
    assert_eq!(TOKEN_SCHEME, "Bearer");
    let token = tokens.mint("c", "t-2", &[0xabu8; 64]).expect("minted");
    for presented in [format!("Bearer {token}"), format!("bearer  {token} ")] {
        assert_eq!(
            tokens
                .claim_of_authorization(&presented)
                .map(|(task, _, _)| task)
                .as_deref(),
            Some("t-2"),
            "{presented}"
        );
    }
    for presented in [format!("Basic {token}"), token.clone(), String::new()] {
        assert_eq!(
            tokens.claim_of_authorization(&presented),
            None,
            "{presented}"
        );
    }
}

#[test]
fn the_credential_round_trips_through_the_record_and_stays_redacted() {
    let a = auth("Bearer", "s3cret");
    let bytes = record_value(&a).expect("serializes");
    assert_eq!(
        bytes, br#"{"scheme":"Bearer","credentials":"s3cret"}"#,
        "the record keeps the plain-string form it always held"
    );
    let back: DeliveryAuth = serde_json::from_slice(&bytes).expect("reads");
    assert_eq!(back, a);
    assert!(!format!("{back:?}").contains("s3cret"));
}

/// A `serde_json` line of the credential (a log line, an assert message) is refused and quotes
/// nothing: only the SDK's record encoder writes it.
#[test]
fn the_credential_serializes_into_the_record_and_nowhere_else() {
    let a = auth("Bearer", "s3cret");
    let e = serde_json::to_string(&a).expect_err("a log line is no record");
    assert!(!e.to_string().contains("s3cret"), "{e}");
    assert!(serde_json::to_value(&a).is_err());
}

/// One `tick` op attempts one notification: the next task's head in turn (task-id order), marked
/// open so the next op takes another; a task's later notification waits behind its open head.
#[test]
fn the_next_due_is_one_head_at_a_time_each_task_in_turn() {
    let d = Deliveries::default();
    assert_eq!(d.next_due(0), None);
    d.enqueue(delivery("t2"), 5 * MS);
    d.enqueue(delivery("t1"), 9 * MS);
    d.enqueue(delivery("t2"), 6 * MS);
    assert_eq!(d.next_due(4 * MS), None, "nothing is due yet");
    assert_eq!(d.next_due(10 * MS).map(|x| x.task_id), Some("t1".into()));
    assert_eq!(d.next_due(10 * MS).map(|x| x.task_id), Some("t2".into()));
    assert_eq!(
        d.next_due(10 * MS),
        None,
        "t2's second waits behind its open head"
    );
    assert_eq!(
        d.settle("t2", Attempted::Delivered, 11 * MS, 0),
        DeliverySettled::Done(vocab::EV_PUSH_DELIVERED)
    );
    assert_eq!(d.next_due(11 * MS).map(|x| x.task_id), Some("t2".into()));
}

/// A delivery is keyed to the caller holding its task: the row's principal.
#[test]
fn a_delivery_names_the_caller_holding_its_task() {
    assert_eq!(delivery("t1").caller, "principal");
}

/// What an attempt owes its chain is taken by its caller only, at most one per task and never for
/// the task the taking piece changes itself; the rest stay owed.
#[test]
fn owed_outcomes_are_taken_per_caller_one_per_task() {
    let d = Deliveries::default();
    let mine = delivery("t1");
    let mut theirs = delivery("t9");
    theirs.caller = "other".into();
    d.owe(&mine, Attempted::Status(503));
    d.owe(&mine, Attempted::Delivered);
    d.owe(&delivery("t2"), Attempted::Judged(DEST_METADATA));
    d.owe(&theirs, Attempted::Delivered);
    let kinds = |owed: Vec<Owed>| -> Vec<(String, &'static str)> {
        owed.into_iter().map(|o| (o.task_id, o.kind)).collect()
    };
    assert_eq!(
        kinds(d.take_owed("principal", Some("t2"))),
        vec![("t1".to_string(), vocab::EV_PUSH_FAILED)]
    );
    assert_eq!(
        kinds(d.take_owed("principal", None)),
        vec![
            ("t1".to_string(), vocab::EV_PUSH_DELIVERED),
            ("t2".to_string(), vocab::EV_PUSH_REFUSED)
        ]
    );
    assert_eq!(d.take_owed("principal", None), Vec::new());
    assert_eq!(
        kinds(d.take_owed("other", None)),
        vec![("t9".to_string(), vocab::EV_PUSH_DELIVERED)]
    );
}

/// The owed book is bounded: past [`MAX_OWED`] the oldest goes, counted.
#[test]
fn the_owed_book_is_bounded_and_counts_what_it_drops() {
    let d = Deliveries::default();
    for i in 0..=MAX_OWED {
        d.owe(&delivery(&format!("t{i}")), Attempted::Delivered);
    }
    assert_eq!(d.unfiled(), 1);
    assert_eq!(
        d.take_counted(),
        (0, 1),
        "reported as a counter's increment, once"
    );
    assert_eq!(d.take_counted(), (0, 0));
    let first = d.take_owed("principal", None);
    assert_eq!(first.len(), MAX_OWED);
    assert_eq!(first[0].task_id, "t1", "t0 was the one dropped");
}

/// `the_callback_mac_is_compared_in_constant_time` (the engine's source-shape guard, ported): the
/// presented MAC on the push callback is compared through the tree's one constant-time primitive,
/// and no variable-time compare of it sits beside that one. A presence-only check would pass a fix
/// that added the helper next to a leftover fast-path `==`.
#[test]
fn the_callback_mac_is_compared_in_constant_time() {
    let source = include_str!("../push.rs");
    let body = source
        .split_once("pub fn verified(")
        .expect("`verified` is the function that compares a presented token")
        .1
        .split_once("\n}\n")
        .expect("the function ends")
        .0;
    assert!(
        body.contains("busbar_contract::constant_time_eq"),
        "the presented MAC is no longer compared through the constant-time primitive: {body}"
    );
    assert!(
        !body.contains("presented ==") && !body.contains("== presented"),
        "a variable-time compare of the presented MAC sits beside the constant-time one: {body}"
    );
}

/// RED (BUSBAR-1.6.0.md Locked Decision #54: logs, audit records, metrics and error text never
/// carry a credential's value): the caller's webhook credential is caller payload the plane holds
/// as a `Cred`, and its bytes reach the sealed `Authorization` field and nothing else. A
/// registered config's `Debug` and the refusal of a credential busbar cannot present (the
/// registration's error path) leave the bytes out (a `Cred` has no `Debug` at all). A refusal that
/// quoted the value back fails here.
#[test]
fn the_push_credential_reaches_the_authorization_field_and_no_debug_or_error_text() {
    let secret = "s3cret-webhook-tok";
    let auth = auth("Bearer", secret);
    assert!(!format!("{auth:?}").contains(secret), "{auth:?}");
    assert!(!format!("{:?}", Some(&auth)).contains(secret));
    assert_eq!(
        sealed_bytes(&auth.authorization("https://hook.example/")),
        format!("Bearer {secret}").as_bytes()
    );

    let registered = crate::local::delivery_auth(&serde_json::json!({
        "authentication": { "scheme": "Bearer", "credentials": secret }
    }))
    .expect("a presentable credential registers")
    .expect("it names one");
    assert_eq!(registered, auth);
    assert!(!format!("{registered:?}").contains(secret));

    let refused = crate::local::delivery_auth(&serde_json::json!({
        "authentication": { "scheme": "Bearer", "credentials": format!("{secret}\u{7}") }
    }))
    .expect_err("a credential with a control byte cannot be presented");
    assert!(!refused.contains(secret), "{refused}");
}

/// EACH ATTEMPT IS BOUNDED BY THE REQUEST DEADLINE (ARCHITECT ruling on a slow push receiver): a
/// webhook has no pool, so the bound is the connector's default, ten seconds, and the request
/// names it rather than `0` ("the op's deadline", which a driver ticket's op does not bound). A
/// receiver that never answers then ends its attempt as a transport error, under the
/// three-attempt rule. RED against an unbounded request.
#[test]
fn a_delivery_attempt_is_bounded_by_the_request_deadline() {
    let d = Deliveries::default();
    assert_eq!(
        d.request(&delivery("t1")).0.timeout_ms,
        10_000,
        "the attempt's request is not bounded by the connector's default deadline"
    );
}

/// THE PUMP SERVES THE TASKS' QUEUES IN TURN, one attempt per task per turn (ARCHITECT ruling on a
/// slow push receiver): a task with several notifications waiting never keeps another task's
/// waiting behind all of them. RED against the longest-waiting-then-lowest-id pick, which serves
/// every notification of `a` before `b`'s one.
#[test]
fn the_pump_serves_each_tasks_queue_in_turn() {
    let d = Deliveries::default();
    d.enqueue(delivery("a"), 0);
    d.enqueue(delivery("a"), 0);
    d.enqueue(delivery("b"), 0);
    let first = d.next_due(0).expect("due").task_id;
    assert_eq!(first, "a");
    d.settle("a", Attempted::Delivered, 0, 0);
    assert_eq!(
        d.next_due(0).map(|x| x.task_id).as_deref(),
        Some("b"),
        "b waited behind a second notification of a"
    );
    d.settle("b", Attempted::Delivered, 0, 0);
    assert_eq!(d.next_due(0).map(|x| x.task_id).as_deref(), Some("a"));
}

/// AN AGENT'S PUSH MOVES ITS TASK ONLY TO A STATE IT REPORTS, AND ONLY WHEN THE TASK IS NOT ALREADY
/// IN IT (`POST /a2a/push`, step 6): an artifact update, a message or any document with no
/// readable `status.state` moves nothing (`202`, nothing recorded, no notification), and a retried
/// push of the state already held queues no second notification. RED: a push with no readable state
/// read as `working`, moving a submitted or input-required task, and a re-reported state queued a
/// notification each time.
#[test]
fn a_push_moves_its_task_only_to_a_new_state_it_reports() {
    use crate::push_serve::push_move;
    use serde_json::json;
    for no_state in [
        json!({ "artifactUpdate": { "taskId": "t", "artifact": { "parts": [] } } }),
        json!({ "kind": "message", "messageId": "m", "parts": [] }),
        json!({ "task": { "id": "t" } }),
        json!({ "status": { "state": "pondering" } }),
    ] {
        for held in [TaskState::Submitted, TaskState::InputRequired] {
            assert_eq!(push_move(held, &no_state), None, "{no_state} on {held:?}");
        }
    }
    let working = json!({ "statusUpdate": { "status": { "state": "TASK_STATE_WORKING" } } });
    assert_eq!(push_move(TaskState::Working, &working), None, "a retry");
    assert_eq!(
        push_move(TaskState::Submitted, &working),
        Some(TaskState::Working)
    );
    assert_eq!(
        push_move(
            TaskState::Working,
            &json!({ "task": { "status": { "state": "completed" } } })
        ),
        Some(TaskState::Completed)
    );
}
