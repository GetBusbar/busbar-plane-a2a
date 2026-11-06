// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The door's half of push delivery, over the test's host records: what a moved task queues, and
//! the chain records an attempt owes.

use busbar_contract::vocab::{EV_PUSH_DELIVERED, EV_PUSH_FAILED};

use super::*;
use crate::a2a::task::TaskState;
use crate::push::DeliveryAuth;
use crate::records::{KIND_PUSH_CONFIG, KIND_TASK_EVENT};
use crate::tasks::tests::{event_key, submitted, Book, ALICE, BOB};
use crate::tasks::{get, task_key};
use crate::TaskEventRow;

/// Alice's task `t1`, moved to `working`, with `callback` on its row.
fn moved(book: &mut Book, callback: &str) -> TaskRow {
    submitted(book, ALICE, "t1", 100);
    let mut held = get(book, ALICE, "t1", 100).unwrap().unwrap();
    held.row.push_callback = callback.to_string();
    book.hold(ALICE, &held);
    let mut out = Vec::new();
    let at = Stamp {
        caller: ALICE,
        request_id: "r",
        now: 200,
    };
    let row = tasks::transition(book, &at, "t1", TaskState::Working, &mut out)
        .unwrap()
        .expect("moved");
    book.apply(&out);
    row
}

fn config(url: &str, auth: Option<DeliveryAuth>) -> PushConfig {
    PushConfig {
        id: "cfg".into(),
        url: url.into(),
        authentication: auth,
        version: String::new(),
    }
}

/// A moved task whose caller registered a push config queues ONE notification, due at once, to
/// the config's URL, presenting the config's credential, and keyed to the caller.
#[test]
fn a_moved_task_with_a_registered_config_queues_its_notification_to_that_config() {
    let mut book = Book::default();
    let row = moved(&mut book, "");
    let auth = DeliveryAuth {
        scheme: "Bearer".into(),
        credentials: busbar_contract::abi::sdk::test_support::chip::cred("tok"),
    };
    let d = Deliveries::default();
    assert!(queue(
        &d,
        &row,
        Some(&config("https://hook.example/cb", Some(auth)))
    ));
    let due = d.next_due(0).expect("due at once");
    assert_eq!(due.url, "https://hook.example/cb");
    assert_eq!(due.caller, ALICE);
    assert_eq!(due.task_id, "t1");
    let body: serde_json::Value = serde_json::from_slice(&due.body).unwrap();
    assert_eq!(body["task"]["status"]["state"], "TASK_STATE_WORKING");
    let (_, sealed) = d.request(&due);
    assert!(sealed
        .into_iter()
        .any(|(_, n, v)| n == b"authorization"
            && crate::push::tests::sealed_bytes(v) == b"Bearer tok"));
}

/// A legacy row URL supplies no durable credential authority; neither it nor an absent callback
/// queues a notification.
#[test]
fn a_legacy_row_callback_without_durable_authority_queues_nothing() {
    let mut book = Book::default();
    let row = moved(&mut book, "https://inline.example/cb");
    let d = Deliveries::default();
    assert!(
        !queue(&d, &row, None),
        "legacy URL without durable credential authority is refused"
    );
    assert!(d.next_due(0).is_none());

    let mut silent_book = Book::default();
    let silent = moved(&mut silent_book, "");
    let quiet = Deliveries::default();
    assert!(!queue(&quiet, &silent, None));
    assert_eq!(quiet.next_tick_ns(), 0, "no tick is wanted");
}

/// The config a moved task's notification goes to is read through the piece's records, under the
/// caller's own key: another caller's config for a task of the same id is never it.
#[test]
fn the_config_is_read_under_the_callers_own_key() {
    let mut book = Book::default();
    let row = moved(&mut book, "");
    let theirs = serde_json::to_vec(&config("https://bob.example/cb", None)).unwrap();
    book.apply(&[Write {
        kind: KIND_PUSH_CONFIG,
        key: task_key(BOB, "t1"),
        value: theirs,
    }]);
    let d = Deliveries::default();
    assert!(!queue_moved(&d, &mut book, ALICE, &row).unwrap());
    let mine = serde_json::to_vec(&config("https://alice.example/cb", None)).unwrap();
    book.apply(&[Write {
        kind: KIND_PUSH_CONFIG,
        key: task_key(ALICE, "t1"),
        value: mine,
    }]);
    assert!(queue_moved(&d, &mut book, ALICE, &row).unwrap());
    assert_eq!(d.next_due(0).expect("due").url, "https://alice.example/cb");
}

/// What an attempt owes is filed on its task's chain as the attempt's record kind, with no request
/// id (no inbound request originates a delivery); another caller's owed outcome is not filed.
#[test]
fn an_owed_outcome_is_filed_on_its_tasks_chain() {
    let mut book = Book::default();
    submitted(&mut book, ALICE, "t1", 100);
    submitted(&mut book, ALICE, "t2", 100);
    let owed = vec![
        Owed {
            caller: ALICE.into(),
            task_id: "t1".into(),
            kind: EV_PUSH_DELIVERED,
        },
        Owed {
            caller: ALICE.into(),
            task_id: "t2".into(),
            kind: EV_PUSH_FAILED,
        },
        Owed {
            caller: BOB.into(),
            task_id: "t1".into(),
            kind: EV_PUSH_DELIVERED,
        },
    ];
    let before = book.publications.len();
    let mut out = Vec::new();
    file_owed(&mut book, ALICE, &owed, 300, &mut out).unwrap();
    book.apply(&out);
    let ev = |task: &str| -> TaskEventRow {
        serde_json::from_slice(
            book.value(KIND_TASK_EVENT, &event_key(ALICE, task, 2))
                .unwrap(),
        )
        .unwrap()
    };
    assert_eq!(ev("t1").kind, EV_PUSH_DELIVERED);
    assert_eq!(ev("t1").request_id, "");
    assert_eq!(ev("t1").ts, 300);
    assert_eq!(ev("t2").kind, EV_PUSH_FAILED);
    assert!(
        out.is_empty(),
        "guarded changes never escape as ordinary output"
    );
    assert_eq!(book.publications.len(), before + 2);
    assert!(
        book.publications[before..]
            .iter()
            .all(|writes| writes.len() == 4
                && writes
                    .iter()
                    .filter(|write| write.kind == crate::records::KIND_TASK_QUOTA)
                    .count()
                    == 2),
        "each acknowledged mutation atomically includes its row, event and both quota records"
    );
}

use busbar_contract::abi::host::service::{DEST_INTERNAL, DEST_PLAINTEXT, DEST_UNRESOLVABLE};
use busbar_contract::vocab::EV_PUSH_REFUSED;

use crate::push::DeliverySettled;

/// A public address a callback resolves to at registration.
const AT_REGISTRATION: &str = "203.0.113.7";

/// One scripted judgement: a verdict and the addresses it judged; `None` = nothing was checked.
type Scripted = Option<(u64, Vec<String>)>;

/// One exchange's framed fields, `(name, value)` in order.
type Fields = Vec<(Vec<u8>, Vec<u8>)>;

/// A host whose judge answers each attempt from a script (the last answer repeats), and whose
/// receiver answers `status`; every judged URL and every send is logged, and every send's framed
/// exchange is read back: the fields the far end is handed, keyed to the URL they went to.
struct TestHost {
    verdicts: Vec<Scripted>,
    status: u16,
    judged: Vec<String>,
    sent: Vec<String>,
    /// Each send's URL and the fields its exchange framed, in send order (a sealed value reads
    /// `<sealed>`).
    framed: Vec<(String, Fields)>,
    /// Each send's whole framed head, sealed values included, in send order: the bytes the far end
    /// is handed.
    heads: Vec<Vec<u8>>,
    /// How many sends answer PENDING before one reaches the receiver.
    pends: u32,
    /// How many attempts were abandoned (their connection closed).
    abandoned: u32,
    /// A receiver that never answers: its exchange ends at the request's deadline, a failed one.
    silent: Option<String>,
}

impl TestHost {
    fn answering(verdicts: Vec<Option<(u64, &[&str])>>, status: u16) -> Self {
        TestHost {
            verdicts: verdicts
                .into_iter()
                .map(|v| {
                    v.map(|(verdict, a)| (verdict, a.iter().copied().map(String::from).collect()))
                })
                .collect(),
            status,
            judged: Vec::new(),
            sent: Vec::new(),
            framed: Vec::new(),
            heads: Vec::new(),
            pends: 0,
            abandoned: 0,
            silent: None,
        }
    }
}

impl Line for TestHost {
    fn judge(&mut self, url: &str) -> Poll<Option<Judgement>> {
        self.judged.push(url.to_string());
        let next = if self.verdicts.len() > 1 {
            self.verdicts.remove(0)
        } else {
            self.verdicts[0].clone()
        };
        Poll::Ready(next.map(|(verdict, addrs)| (verdict, addrs.join(","))))
    }

    fn send(&mut self, ex: &mut Exchange, url: &str) -> Poll<Option<u16>> {
        if self.pends > 0 {
            self.pends -= 1;
            return Poll::Pending;
        }
        self.sent.push(url.to_string());
        if self.silent.as_deref() == Some(url) {
            return Poll::Ready(None);
        }
        let fields = ex
            .framed_fields()
            .into_iter()
            .map(|(name, value)| (name.to_vec(), value.to_vec()))
            .collect();
        self.framed.push((url.to_string(), fields));
        self.heads
            .push(busbar_contract::abi::sdk::test_support::chip::framed_head(
                ex,
            ));
        Poll::Ready(Some(self.status))
    }

    fn jitter(&mut self) -> u8 {
        128
    }

    fn abandon(&mut self, _stream: Option<u64>) {
        self.abandoned += 1;
    }
}

/// A `completed` task of Alice's with `callback`, its notification queued with a credential.
fn queued(callback: &str) -> Deliveries {
    let mut book = Book::default();
    let mut row = moved(&mut book, callback);
    row.state = "completed".into();
    let d = Deliveries::default();
    let auth = DeliveryAuth {
        scheme: "Bearer".into(),
        credentials: busbar_contract::abi::sdk::test_support::chip::cred("tok"),
    };
    assert!(queue(&d, &row, Some(&config(callback, Some(auth)))));
    d
}

/// One `tick`'s attempt at `now_ns`, settled as the tick settles it.
fn tick_once(d: &Deliveries, host: &mut TestHost, now_ns: u64) -> (Attempted, DeliverySettled) {
    let delivery = d.next_due(now_ns).expect("a delivery is due");
    let mut flight = Flight {
        delivery,
        exchange: None,
        config_read: None,
    };
    let Poll::Ready(end) = attempt(host, d, &mut flight) else {
        panic!("the test's host never pends");
    };
    d.owe(&flight.delivery, end);
    (end, d.settle(&flight.delivery.task_id, end, now_ns, 128))
}

/// The base case: a completed task with a callback is POSTed to it once, and its delivered record is
/// owed; its last delivery drops the credential.
#[test]
fn a_completed_task_with_a_callback_is_delivered() {
    let callback = "https://hook.caller.test/notify";
    let d = queued(callback);
    let mut host = TestHost::answering(vec![Some((DEST_ALLOWED, &[AT_REGISTRATION][..]))], 200);
    let (end, settled) = tick_once(&d, &mut host, 0);
    assert_eq!(end, Attempted::Delivered);
    assert_eq!(settled, DeliverySettled::Done(EV_PUSH_DELIVERED));
    assert_eq!(host.sent, vec![callback.to_string()]);
    assert_eq!(d.take_owed(ALICE, None)[0].kind, EV_PUSH_DELIVERED);
}

/// A callback that resolves to an internal address at DELIVERY (it passed at registration) is
/// refused by the judge on this attempt, and nothing is sent.
#[test]
fn a_callback_that_became_internal_after_registration_is_refused_at_delivery() {
    let d = queued("https://hook.caller.test/notify");
    let mut host = TestHost::answering(vec![Some((DEST_INTERNAL, &[][..]))], 200);
    let (end, settled) = tick_once(&d, &mut host, 0);
    assert_eq!(end, Attempted::Judged(DEST_INTERNAL));
    assert_eq!(
        settled,
        DeliverySettled::Done(EV_PUSH_REFUSED),
        "never retried"
    );
    assert!(host.sent.is_empty(), "refused before the socket");
}

/// THE CALLER'S OWN CREDENTIAL IS PRESENTED, and it is the caller's — not busbar's (ported from the
/// engine's `pushdeliver_tests.rs::the_callers_own_webhook_credential_is_presented_on_the_delivery`,
/// the `egress-auth × a2a-server` cell). A caller whose webhook authenticates registers its
/// `authentication` with the push config; the exchange the attempt actually frames and sends, once
/// the judge admits the callback, carries exactly one `authorization` field, `<scheme>
/// <credentials>` as RFC 9110 spells it and as the caller wrote it. Read off the SENT exchange, as
/// predev read its sent log: framing the attempt without the held credential, or an exchange that
/// drops the field, reds here. The credential is never printed: a failure names the field, not its
/// value.
#[test]
fn the_callers_own_webhook_credential_is_presented_on_the_delivery() {
    let callback = "https://hook.caller.test/notify";
    let mut book = Book::default();
    let row = moved(&mut book, callback);
    let d = Deliveries::default();
    let auth = DeliveryAuth {
        scheme: "Bearer".into(),
        credentials: busbar_contract::abi::sdk::test_support::chip::cred("receiver-issued-token"),
    };
    assert!(queue(&d, &row, Some(&config(callback, Some(auth)))));
    let mut host = TestHost::answering(vec![Some((DEST_ALLOWED, &[AT_REGISTRATION][..]))], 200);
    let (end, _) = tick_once(&d, &mut host, 0);
    assert_eq!(end, Attempted::Delivered);
    assert_eq!(
        host.sent,
        vec![callback.to_string()],
        "the delivery is sent once, to the caller's callback"
    );
    assert_eq!(host.framed.len(), 1, "one exchange was framed and sent");
    let (url, fields) = &host.framed[0];
    assert_eq!(
        url, callback,
        "the framed exchange is the one sent to the callback"
    );
    let presented: Vec<&[u8]> = fields
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case(b"authorization"))
        .map(|(_, value)| value.as_slice())
        .collect();
    assert_eq!(
        presented.len(),
        1,
        "the sent exchange carries {} authorization field(s), not exactly one",
        presented.len()
    );
    assert!(
        presented[0] == b"<sealed>".as_slice(),
        "the sent exchange's authorization field is not sealed"
    );
    let wanted = b"Bearer receiver-issued-token".as_slice();
    assert_eq!(
        host.heads[0]
            .windows(wanted.len())
            .filter(|w| *w == wanted)
            .count(),
        1,
        "the sent head does not carry the credential the caller registered, once"
    );
}

/// A name that resolves to nothing at delivery, or a judgement that could not be made, is refused:
/// nothing was checked, so nothing is allowed.
#[test]
fn a_name_that_resolves_to_nothing_at_delivery_time_is_refused() {
    for script in [Some((DEST_UNRESOLVABLE, &[][..])), None] {
        let d = queued("https://hook.caller.test/notify");
        let mut host = TestHost::answering(vec![script], 200);
        let (end, _) = tick_once(&d, &mut host, 0);
        assert_eq!(
            end,
            if script.is_some() {
                Attempted::Judged(DEST_UNRESOLVABLE)
            } else {
                Attempted::Transport
            }
        );
        assert!(host.sent.is_empty());
    }
}

/// A private address is refused with no socket: no exchange is framed and nothing is sent, so the
/// caller's credential reaches no refused destination.
#[test]
fn a_private_address_is_refused_with_no_socket() {
    let d = queued("https://hook.caller.test/notify");
    let mut host = TestHost::answering(vec![Some((DEST_INTERNAL, &[][..]))], 200);
    let delivery = d.next_due(0).expect("due");
    let mut flight = Flight {
        delivery,
        exchange: None,
        config_read: None,
    };
    let _ = attempt(&mut host, &d, &mut flight);
    assert!(flight.exchange.is_none(), "no request was framed");
    assert!(host.sent.is_empty(), "no socket");
}

/// A plaintext callback that reached a row is refused at DELIVERY on the host's verdict (the
/// open-web class admits a secure connection only), and nothing is sent.
#[test]
fn a_plaintext_callback_is_refused_at_delivery() {
    let callback = "http://hook.caller.test/notify";
    let d = queued(callback);
    let mut host = TestHost::answering(vec![Some((DEST_PLAINTEXT, &[][..]))], 200);
    let (end, settled) = tick_once(&d, &mut host, 0);
    assert_eq!(end, Attempted::Judged(DEST_PLAINTEXT));
    assert_eq!(settled, DeliverySettled::Done(EV_PUSH_REFUSED));
    assert_eq!(host.judged, vec![callback.to_string()]);
    assert!(host.sent.is_empty());
}

/// The judge is asked again on the retry: a receiver that failed with a `503` is retried, and the
/// retry's fresh verdict (now internal) refuses it before anything is sent a second time.
#[test]
fn the_guard_is_re_run_on_the_retry() {
    let d = queued("https://hook.caller.test/notify");
    let mut host = TestHost::answering(
        vec![
            Some((DEST_ALLOWED, &[AT_REGISTRATION][..])),
            Some((DEST_INTERNAL, &[][..])),
        ],
        503,
    );
    let (first, settled) = tick_once(&d, &mut host, 0);
    assert_eq!(first, Attempted::Status(503));
    let DeliverySettled::Retry(at) = settled else {
        panic!("a 503 is retried: {settled:?}");
    };
    let (second, settled) = tick_once(&d, &mut host, at);
    assert_eq!(second, Attempted::Judged(DEST_INTERNAL));
    assert_eq!(settled, DeliverySettled::Done(EV_PUSH_REFUSED));
    assert_eq!(host.judged.len(), 2, "judged on every attempt");
    assert_eq!(host.sent.len(), 1, "the retry sent nothing");
}

/// A deleted config withdraws the queued attempt. An already borrowed delivery keeps its immutable
/// URL/auth snapshot, so the pump must check current() before using it.
#[test]
fn a_deleted_config_withdraws_the_captured_delivery_before_it_can_be_sent() {
    let callback = "https://hook.caller.test/notify";
    let d = queued(callback);
    let due = d.next_due(0).expect("due");
    let presented = |d: &Deliveries| {
        d.request(&due)
            .1
            .iter()
            .any(|(_, n, _)| n == b"authorization")
    };
    let tombstone = |caller: &str| Write {
        kind: KIND_PUSH_CONFIG,
        key: task_key(caller, "t1"),
        value: Vec::new(),
    };
    let written = Write {
        kind: KIND_PUSH_CONFIG,
        key: task_key(ALICE, "t1"),
        value: b"{}".to_vec(),
    };
    forget_deleted(&d, &[tombstone(BOB), written]);
    assert!(presented(&d), "nothing of Alice's was deleted");
    assert!(d.current(&due));
    forget_deleted(&d, &[tombstone(ALICE)]);
    assert!(
        !d.current(&due),
        "the pump must abandon the withdrawn snapshot"
    );
    assert!(d.next_due(0).is_none(), "no queued delivery remains");
    assert!(
        presented(&d),
        "a borrowed snapshot is immutable until its owner drops it"
    );
}

/// A queued notification wakes the instance's driver ticket (R-PUSH), so the kernel ticks and
/// attempts it at once; a task that queues nothing wakes nothing; an unarmed wake is a no-op.
#[test]
fn a_queued_notification_wakes_the_driver_ticket() {
    let mut book = Book::default();
    let row = moved(&mut book, "https://inline.example/cb");
    let authority = config("https://inline.example/cb", None);
    let (told, woken) = std::sync::mpsc::channel::<()>();
    let d = Deliveries::default();
    assert!(
        queue(&d, &row, Some(&authority)),
        "unarmed: queued, no wake to make"
    );
    d.arm(|| {
        Box::new(move || {
            let _ = told.send(());
        })
    });
    d.arm(|| panic!("armed once"));
    assert_eq!(woken.try_iter().count(), 0, "arming wakes nothing");
    assert!(queue(&d, &row, Some(&authority)));
    assert_eq!(woken.try_iter().count(), 1, "queue wakes the ticket");
    let silent = moved(&mut Book::default(), "");
    assert!(!queue(&d, &silent, None));
    assert_eq!(woken.try_iter().count(), 0, "nothing queued, nothing woken");
}

/// The pushback path (`queue_moved`, the agent's own report of a task's move) wakes the driver
/// ticket after queueing the caller's delivery.
#[test]
fn queue_moved_wakes_the_driver_ticket() {
    let mut book = Book::default();
    let row = moved(&mut book, "https://inline.example/cb");
    book.apply(&[Write {
        kind: KIND_PUSH_CONFIG,
        key: task_key(ALICE, &row.task_id),
        value: serde_json::to_vec(&config("https://inline.example/cb", None)).unwrap(),
    }]);
    let (told, woken) = std::sync::mpsc::channel::<()>();
    let d = Deliveries::default();
    d.arm(|| {
        Box::new(move || {
            let _ = told.send(());
        })
    });
    assert!(queue_moved(&d, &mut book, ALICE, &row).unwrap());
    assert_eq!(woken.try_iter().count(), 1);
}

/// A delivery is never sent twice (R-PUSH): a `tick` whose exchange pends holds the attempt, and a
/// second `tick` while it is held starts nothing and calls nothing; `drive` alone carries it on, and
/// the receiver is reached EXACTLY once. RED against a variant where the tick and drive both
/// deliver (two receiver hits).
#[test]
fn a_pending_attempt_is_delivered_once_whether_tick_or_drive_runs_first() {
    let callback = "https://hook.caller.test/notify";
    let d = queued(callback);
    let attempting = Attempting::default();
    let mut host = TestHost::answering(vec![Some((DEST_ALLOWED, &[AT_REGISTRATION][..]))], 200);
    host.pends = 1;
    assert_eq!(tick_over(&mut host, &d, &attempting, 0), Outcome::Pending);
    assert!(host.sent.is_empty(), "the exchange is still in flight");
    let judged = host.judged.len();

    assert_eq!(tick_over(&mut host, &d, &attempting, 1), Outcome::Ready);
    assert_eq!(
        host.judged.len(),
        judged,
        "a held attempt makes no host call"
    );
    assert!(host.sent.is_empty(), "the tick did not deliver");

    assert_eq!(drive_over(&mut host, &d, &attempting), Outcome::Ready);
    assert_eq!(host.sent, vec![callback.to_string()], "exactly one request");

    assert_eq!(drive_over(&mut host, &d, &attempting), Outcome::Ready);
    assert_eq!(tick_over(&mut host, &d, &attempting, 2), Outcome::Ready);
    assert_eq!(host.sent.len(), 1, "never sent twice");
    assert_eq!(d.take_owed(ALICE, None).len(), 1, "one outcome owed");
}

/// A lost wake still ends in exactly one delivery (R-PUSH, coordinator option (b)): an attempt left
/// held with no `drive` is abandoned by the first tick past the whole attempt's deadline (ten
/// seconds), which is asked for at that moment, and its delivery is requeued under the
/// retry rules and then sent once. RED against round 2's behaviour (a held attempt is never given
/// up): nothing is ever sent.
#[test]
fn a_dropped_wake_ends_in_exactly_one_delivery_after_the_timeout() {
    let callback = "https://hook.caller.test/notify";
    let d = queued(callback);
    let attempting = Attempting::default();
    let mut host = TestHost::answering(vec![Some((DEST_ALLOWED, &[AT_REGISTRATION][..]))], 200);
    host.pends = 1;
    let start = 1_000;
    assert_eq!(
        tick_over(&mut host, &d, &attempting, start),
        Outcome::Pending
    );
    assert_eq!(
        next_tick_ns(&d, &attempting),
        start + DELIVERY_TIMEOUT_NS,
        "the tick is asked for at the abandonment"
    );

    assert_eq!(
        tick_over(&mut host, &d, &attempting, start + 1),
        Outcome::Ready
    );
    assert_eq!(host.abandoned, 0);

    let at = start + DELIVERY_TIMEOUT_NS;
    assert_eq!(tick_over(&mut host, &d, &attempting, at), Outcome::Ready);
    assert_eq!(host.abandoned, 1, "the attempt's connection was closed");
    assert!(
        host.sent.is_empty(),
        "the requeue waits out its retry delay"
    );
    assert_eq!(attempting.deadline_ns(), 0, "nothing is held");
    let again = next_tick_ns(&d, &attempting);
    assert!(again > at, "the retry is asked for: {again}");
    assert_eq!(tick_over(&mut host, &d, &attempting, again), Outcome::Ready);
    assert_eq!(
        host.sent,
        vec![callback.to_string()],
        "exactly one delivery"
    );
    assert_eq!(
        next_tick_ns(&d, &attempting),
        0,
        "nothing is left to tick for"
    );
}

/// An attempt cancelled by abandonment never also completes: the connection it held is closed, and
/// a late `drive` (the old connection's answer arriving) finds nothing to carry on, so the
/// receiver is reached once, by the requeued attempt. RED against a variant that abandons without
/// dropping the attempt (the late drive sends it a second time).
#[test]
fn an_abandoned_attempt_never_also_completes() {
    let callback = "https://hook.caller.test/notify";
    let d = queued(callback);
    let attempting = Attempting::default();
    let mut host = TestHost::answering(vec![Some((DEST_ALLOWED, &[AT_REGISTRATION][..]))], 200);
    host.pends = 1;
    assert_eq!(tick_over(&mut host, &d, &attempting, 0), Outcome::Pending);
    let at = DELIVERY_TIMEOUT_NS;
    assert_eq!(tick_over(&mut host, &d, &attempting, at), Outcome::Ready);
    assert_eq!(host.abandoned, 1);

    assert_eq!(drive_over(&mut host, &d, &attempting), Outcome::Ready);
    assert!(
        host.sent.is_empty(),
        "the abandoned attempt did not complete"
    );
    let again = next_tick_ns(&d, &attempting);
    assert_eq!(tick_over(&mut host, &d, &attempting, again), Outcome::Ready);
    assert_eq!(drive_over(&mut host, &d, &attempting), Outcome::Ready);
    assert_eq!(
        host.sent,
        vec![callback.to_string()],
        "reached exactly once"
    );
    assert_eq!(host.abandoned, 1);
}

/// A RETRY'S WAIT IS COUNTED FROM WHEN THE ATTEMPT ENDED (spec l.391-392: three attempts, two
/// delays of 250/500 ms ±20 %). An attempt whose exchange pends, and whose `503` arrives two
/// seconds after the tick that began it, is not retried on the tick that follows its `drive`: the
/// retry waits out its 250 ms from then. RED against a wait counted from the attempt's start (the
/// delay is already spent when the failure lands, so the retry goes out at once).
#[test]
fn a_retry_waits_from_when_a_pended_attempt_ended() {
    let callback = "https://hook.caller.test/notify";
    let d = queued(callback);
    let attempting = Attempting::default();
    let mut host = TestHost::answering(vec![Some((DEST_ALLOWED, &[AT_REGISTRATION][..]))], 503);
    host.pends = 1;
    assert_eq!(tick_over(&mut host, &d, &attempting, 0), Outcome::Pending);

    assert_eq!(drive_over(&mut host, &d, &attempting), Outcome::Ready);
    assert_eq!(host.sent.len(), 1, "the first attempt reached the receiver");

    let ended = 2_000_000_000;
    assert_eq!(tick_over(&mut host, &d, &attempting, ended), Outcome::Ready);
    assert_eq!(
        host.sent.len(),
        1,
        "the retry went out at once, with no delay after the failure"
    );
    let again = next_tick_ns(&d, &attempting);
    assert!(
        again >= ended + 200_000_000 && again <= ended + 300_000_000,
        "the retry is asked for 250 ms ±20 % after the attempt ended: {again}"
    );
    assert_eq!(tick_over(&mut host, &d, &attempting, again), Outcome::Ready);
    assert_eq!(
        host.sent.len(),
        2,
        "the retry goes out once its wait is over"
    );
}

/// A RECEIVER WHOSE ADDRESSES CHANGED IS STILL DELIVERED TO: the destination judge runs on every
/// attempt and the dial lands only within what it judged (spec l.392-393, "re-runs the destination
/// judge on every attempt"; THE DESIGN, its connections section: the connector judges every open),
/// so a fresh, allowed resolution that shares no address with an earlier delivery's is reached. RED
/// against a plane-side rule that refuses it (`Moved`) for as long as the instance lives.
#[test]
fn a_receiver_whose_addresses_changed_is_still_delivered() {
    let callback = "https://hook.caller.test/notify";
    let d = queued(callback);
    let mut host = TestHost::answering(
        vec![
            Some((DEST_ALLOWED, &[AT_REGISTRATION][..])),
            Some((DEST_ALLOWED, &["198.51.100.9"][..])),
        ],
        200,
    );
    let (first, _) = tick_once(&d, &mut host, 0);
    assert_eq!(first, Attempted::Delivered);
    d.enqueue(
        Delivery {
            task_id: "t2".into(),
            caller: ALICE.into(),
            url: callback.into(),
            body: Vec::new(),
            terminal: false,
            auth: None,
            from_config: false,
            unresolved: None,
        },
        0,
    );
    let (second, settled) = tick_once(&d, &mut host, 0);
    assert_eq!(
        second,
        Attempted::Delivered,
        "the judged, allowed new address was refused"
    );
    assert_eq!(settled, DeliverySettled::Done(EV_PUSH_DELIVERED));
    assert_eq!(
        host.sent.len(),
        2,
        "both notifications reached the receiver"
    );
}

/// A terminal task without a durable config has no notification authority to retain.
#[test]
fn terminal_task_without_durable_config_queues_nothing() {
    let mut book = Book::default();
    let mut row = moved(&mut book, "");
    row.state = "completed".into();
    let deliveries = Deliveries::default();
    assert!(!queue(&deliveries, &row, None));
    assert!(deliveries.next_due(0).is_none());
}

/// AN ENDED TASK SPENDS ITS CALLBACK TOKEN, whichever move ended it: the token busbar registered
/// with the agent is released when the move is terminal, so tasks that end through the relayed
/// answer or a refresh never pile up against `MAX_TOKENS`; a live task keeps its token.
#[test]
fn an_ended_task_spends_its_callback_token() {
    let mut book = Book::default();
    let mut row = moved(&mut book, "");
    let tokens = crate::push::Tokens::default();
    let token = tokens.mint(ALICE, "t1", &[7u8; 32]).expect("minted");
    ended(&tokens, &row);
    assert!(
        tokens.claim(&token).is_some(),
        "a working task keeps its token"
    );
    row.state = "completed".into();
    ended(&tokens, &row);
    assert!(
        tokens.claim(&token).is_none(),
        "the ended task's token is spent"
    );
}

/// A NOTIFICATION QUEUED WHILE AN ATTEMPT IS HELD DOES NOT WAKE THE DRIVER TICKET: the wake would
/// make the kernel tick, and a tick's start is the driver ticket's cycle boundary, which forgets
/// the held attempt's pending exchange (its completion lost, the attempt ended only by its
/// deadline's abandonment, a replay dialling again). The queued notification waits; the held attempt's own
/// completion wake carries it, and the held attempt ends with its own result, sent once. RED
/// against a queue that wakes while an attempt is held.
#[test]
fn a_notification_queued_during_a_held_attempt_waits_for_that_attempts_own_wake() {
    let callback = "https://hook.caller.test/notify";
    let mut book = Book::default();
    let row = moved(&mut book, callback);
    let authority = config(callback, None);
    let d = Deliveries::default();
    let (told, woken) = std::sync::mpsc::channel::<()>();
    d.arm(|| {
        Box::new(move || {
            let _ = told.send(());
        })
    });
    assert!(queue(&d, &row, Some(&authority)));
    assert_eq!(woken.try_iter().count(), 1, "nothing held: the queue wakes");
    let attempting = Attempting::default();
    let mut host = TestHost::answering(vec![Some((DEST_ALLOWED, &[AT_REGISTRATION][..]))], 200);
    host.pends = 1;
    assert_eq!(tick_over(&mut host, &d, &attempting, 0), Outcome::Pending);
    let mut other = row.clone();
    other.task_id = "t2".into();
    assert!(
        queue(&d, &other, Some(&authority)),
        "the notification is recorded"
    );
    assert_eq!(
        woken.try_iter().count(),
        0,
        "a queue during a held attempt woke the driver ticket"
    );

    assert_eq!(drive_over(&mut host, &d, &attempting), Outcome::Ready);
    assert!(
        woken.try_iter().count() > 0,
        "completion must wake queued work"
    );
    assert_eq!(host.sent, vec![callback.to_string()], "sent once");
    assert_eq!(d.take_owed(ALICE, None).len(), 1, "its own result is owed");

    assert_eq!(tick_over(&mut host, &d, &attempting, 1), Outcome::Ready);
    assert_eq!(host.sent.len(), 2, "the queued notification goes next");
}

/// A silent receiver can delay another task's delivery by at most one attempt deadline.
#[test]
fn a_silent_receiver_delays_another_tasks_delivery_by_one_deadline_at_most() {
    let silent = "https://silent.caller.test/notify";
    let prompt = "https://prompt.caller.test/notify";
    let d = Deliveries::default();
    for (task, url) in [("a", silent), ("b", prompt)] {
        d.enqueue(
            Delivery {
                task_id: task.into(),
                caller: ALICE.into(),
                url: url.into(),
                body: Vec::new(),
                terminal: false,
                auth: None,
                from_config: false,
                unresolved: None,
            },
            0,
        );
    }
    let attempting = Attempting::default();
    let mut host = TestHost::answering(vec![Some((DEST_ALLOWED, &[AT_REGISTRATION][..]))], 200);
    host.silent = Some(silent.to_string());
    host.pends = 1;
    assert_eq!(tick_over(&mut host, &d, &attempting, 0), Outcome::Pending);

    assert_eq!(drive_over(&mut host, &d, &attempting), Outcome::Ready);
    let deadline = crate::push::ATTEMPT_TIMEOUT_MS * 1_000_000;
    assert_eq!(
        tick_over(&mut host, &d, &attempting, deadline),
        Outcome::Ready
    );
    assert_eq!(
        host.sent,
        vec![silent.to_string(), prompt.to_string()],
        "the second task's delivery lands within one deadline"
    );
}

/// The ten-second deadline bounds the whole attempt from the tick that began it.
#[test]
fn the_whole_attempt_is_abandoned_at_ten_seconds_as_a_transport_error() {
    let d = queued("https://hook.caller.test/notify");
    let attempting = Attempting::default();
    let mut host = TestHost::answering(vec![Some((DEST_ALLOWED, &[AT_REGISTRATION][..]))], 200);
    host.pends = 1;
    assert_eq!(tick_over(&mut host, &d, &attempting, 0), Outcome::Pending);
    let ten_s = 10_000_000_000;
    assert_eq!(
        next_tick_ns(&d, &attempting),
        ten_s,
        "the tick is not asked for at the whole attempt's ten-second deadline"
    );
    assert_eq!(tick_over(&mut host, &d, &attempting, ten_s), Outcome::Ready);
    assert_eq!(
        host.abandoned, 1,
        "the attempt was not abandoned at ten seconds"
    );
    assert_eq!(
        d.take_owed(ALICE, None)[0].kind,
        EV_PUSH_FAILED,
        "the abandoned attempt is a transport error"
    );
    assert!(
        next_tick_ns(&d, &attempting) > ten_s,
        "its retry is asked for"
    );
}

/// WHILE AN ATTEMPT IS HELD THE TICK IS ASKED FOR ONLY AT ITS ABANDONMENT, never at once for a
/// delivery that came due meanwhile: such a tick starts no attempt (the held one is `drive`'s), and
/// its start is the driver ticket's cycle boundary, which forgets the held exchange's answers. The
/// held attempt's own completion wake attempts what waits. RED against a tick asked for at the
/// earliest of the due delivery and the deadline (the instance ticks at once, over and over).
#[test]
fn a_held_attempt_asks_for_no_tick_before_its_deadline() {
    let d = queued("https://hook.caller.test/notify");
    let attempting = Attempting::default();
    let mut host = TestHost::answering(vec![Some((DEST_ALLOWED, &[AT_REGISTRATION][..]))], 200);
    host.pends = 1;
    let start = 1_000;
    assert_eq!(
        tick_over(&mut host, &d, &attempting, start),
        Outcome::Pending
    );
    d.enqueue(
        Delivery {
            task_id: "t2".into(),
            caller: ALICE.into(),
            url: "https://other.caller.test/notify".into(),
            body: Vec::new(),
            terminal: false,
            auth: None,
            from_config: false,
            unresolved: None,
        },
        start,
    );
    assert_eq!(
        next_tick_ns(&d, &attempting),
        start + DELIVERY_TIMEOUT_NS,
        "a due delivery asked for a tick while an attempt is held"
    );

    assert_eq!(drive_over(&mut host, &d, &attempting), Outcome::Ready);
    assert_eq!(next_tick_ns(&d, &attempting), start);
}

#[path = "push_delivery_custody.rs"]
mod delivery_custody;

#[path = "push_deferred_custody.rs"]
mod deferred_custody;

#[test]
fn acknowledged_retention_config_deletes_clean_the_actual_other_caller_queue() {
    let mut book = Book::default();
    let mine = moved(&mut book, "");
    let mut theirs = mine.clone();
    theirs.task_id = "t2".into();
    theirs.principal = BOB.into();
    let d = Deliveries::default();
    let cfg = config("https://receiver.example/cb", None);
    assert!(queue(&d, &mine, Some(&cfg)));
    assert!(queue(&d, &theirs, Some(&cfg)));
    assert_eq!(d.depth("t1"), 1);
    assert_eq!(d.depth("t2"), 1);
    forget_deleted(
        &d,
        &[Write {
            kind: KIND_PUSH_CONFIG,
            key: task_key(BOB, "t2"),
            value: Vec::new(),
        }],
    );
    assert_eq!(d.depth("t1"), 1);
    assert_eq!(
        d.depth("t2"),
        0,
        "retention acknowledgement uses its actual stored caller/key"
    );
}

use crate::push::Owed;
use crate::tasks::{Records, Write};

pub fn queue(deliveries: &Deliveries, row: &TaskRow, config: Option<&PushConfig>) -> bool {
    let Some(delivery) = captured(row, config) else {
        return false;
    };
    deliveries.enqueue(delivery, 0);

    deliveries.wake();
    true
}

pub fn forget_deleted(deliveries: &Deliveries, writes: &[Write]) {
    for w in writes
        .iter()
        .filter(|w| w.kind == KIND_PUSH_CONFIG && w.value.is_empty())
    {
        deliveries.forget_config(&w.key);
    }
}

pub fn queue_moved(
    deliveries: &Deliveries,
    rec: &mut dyn Records,
    caller: &str,
    row: &TaskRow,
) -> Result<bool, Halt> {
    match local::held_config(rec, caller, &row.task_id) {
        Ok(config) => Ok(queue(deliveries, row, config.as_ref())),
        Err(Halt::Pending) => Err(Halt::Pending),
        Err(Halt::Failed(_)) => {
            defer(deliveries, row);
            Ok(true)
        }
    }
}

pub(crate) fn defer(deliveries: &Deliveries, row: &TaskRow) {
    deliveries.enqueue(deferred(row), 0);
    busbar_contract::diag_warn!(
        crate::diagnostics::A2A_PUSH_CHECK_UNAVAILABLE,
        "a2a: notification config unavailable; retained for delivery retry"
    );
    deliveries.wake();
}

pub fn file_owed(
    rec: &mut dyn Records,
    caller: &str,
    owed: &[Owed],
    now_s: u64,
    out: &mut Vec<Write>,
) -> Result<(), Halt> {
    for o in owed.iter().filter(|o| o.caller == caller) {
        let at = Stamp {
            caller,
            request_id: "",
            now: now_s,
        };
        if let Err(Halt::Pending) = tasks::record_push_delivery(rec, &at, &o.task_id, o.kind, out) {
            return Err(Halt::Pending);
        }
    }
    Ok(())
}
