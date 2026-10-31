// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Push delivery, driven by the door: the host's half of [`crate::push`].
//!
//! * A relayed task that MOVES queues its notification ([`queue`]): to the push_config host record
//!   the caller registered for it, or else to the callback its row carries (an inline config). A
//!   task with neither queues nothing.
//! * The lifecycle `tick` ([`tick_deliveries`]) attempts ONE due notification per op: the kernel's random
//!   byte for the retry's jitter, then the destination judge over the callback, its name resolved,
//!   then one exchange over the plane's outbound `open-web` need
//!   ([`crate::statement::NEED_OPEN_WEB`]) landing only on the addresses it judged. Judging a
//!   destination is the host's (the connector judges every
//!   open); the plane keeps no address rule of its own. An attempt whose exchange pends ends its `tick` PENDING (a driver ticket's op is never resumed) and goes on
//!   through `drive` ([`drive`]), held in plane memory across the entries, each making the same host
//!   calls in the same order (the replay rule). Its end settles the queue and is OWED to the task's
//!   chain. A queued notification wakes the driver ticket ([`queue`]), so the kernel runs `drive`
//!   and then re-polls `tick` to attempt it at once.
//! * A relayed piece of the same caller FILES what is owed ([`file_owed`]), one chain change per
//!   task, never on the task the piece itself moves. A plane's record writes ride `on_piece`'s
//!   answer and nothing else, so a `tick` writes none and an attempt's outcome reaches its chain
//!   on its caller's next relayed answer.

use std::task::Poll;

use busbar_contract::abi::host::service::{DEST_ALLOWED, DEST_UNRESOLVABLE};
use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::mechanism::ticket::{CompletionHandle, Ticket};
use busbar_contract::abi::sdk::conn::StaticHost;
use busbar_contract::abi::sdk::exchange::{exchange, Exchange};
use busbar_contract::abi::sdk::publish::Keyed;
use busbar_contract::abi::sdk::{Instance, ServiceError, StaticServices};

use crate::a2a::task::Task;
use crate::local::{self, PushConfig};
use crate::plane_door::A2aDoor;
use crate::push::{Attempted, Deliveries, Delivery, DeliverySettled, Owed, Tokens};
use crate::records::KIND_PUSH_CONFIG;
use crate::statement::NEED_OPEN_WEB;
use crate::tasks::{self, Halt, Records, Stamp, Write};
use crate::TaskRow;

/// The jitter byte that moves a retry's wait by nothing: used when the host lends no random byte
/// (a delay is a timing nicety, not a security property).
const NO_JITTER: u8 = 128;

/// QUEUE the notification `row`'s move owes: to `config` (the push_config record of the task) when
/// the caller registered one, carrying that config's credential; else to the row's own callback,
/// carrying the inline credential held for that URL. The delivery takes its credential NOW, with
/// its URL, so it never presents one registered later for another. Due at once: the next `tick`
/// attempts it. (The book's times are the `tick`'s clock, which a piece does not read, so a first
/// attempt is filed as due at its origin.) Answers whether one was queued.
pub fn queue(deliveries: &Deliveries, row: &TaskRow, config: Option<&PushConfig>) -> bool {
    let Ok(mut task) = Task::from_row(row) else {
        return false;
    };
    let from_config = config.is_some();
    let auth = match config {
        Some(cfg) => {
            task.push_callback = Some(cfg.url.clone());
            task.push_version.clone_from(&cfg.version);
            cfg.authentication.clone()
        }
        None => task
            .push_callback
            .as_deref()
            .and_then(|url| deliveries.inline_auth(&task.task_id, url)),
    };
    // An ended task's inline credential is not held past this, its last delivery (which carries
    // its own copy), or past an end with nothing to deliver.
    if task.state.is_terminal() {
        deliveries.drop_inline(&task.task_id);
    }
    let Some(mut delivery) = Delivery::of(&task) else {
        return false;
    };
    delivery.auth = auth;
    delivery.from_config = from_config;
    deliveries.enqueue(delivery, 0);
    // The delivery is attempted on this wake of the driver ticket, not at the next scheduled tick;
    // while an attempt is held, on that attempt's own completion wake ([`Deliveries::wake`]).
    deliveries.wake();
    true
}

/// RELEASE busbar's own callback token for `row`'s task once the move has ENDED it, whichever way
/// it ended (the relayed answer, a cancel, a mirror refresh, the agent's own push): an ended task
/// has nothing left to report, and a token held past it would count against
/// [`crate::push::MAX_TOKENS`] for the life of the instance.
pub fn ended(tokens: &Tokens, row: &TaskRow) {
    if Task::from_row(row).is_ok_and(|t| t.state.is_terminal()) {
        tokens.forget(&row.task_id);
    }
}

/// Forget what every push config `writes` deletes for `caller` (the tombstone of its task's config
/// record) was queued for ([`Deliveries::forget_task`]): a notification and a secret with no config
/// left to deliver them for do not stay in plane memory.
pub fn forget_deleted(deliveries: &Deliveries, caller: &str, writes: &[Write]) {
    let prefix = tasks::task_key(caller, "");
    for w in writes
        .iter()
        .filter(|w| w.kind == KIND_PUSH_CONFIG && w.value.is_empty())
    {
        if let Some(task_id) = w.key.strip_prefix(prefix.as_str()) {
            deliveries.forget_task(task_id);
        }
    }
}

/// [`queue`] for a relayed piece of `caller`'s that moved `row`: the task's push_config record read
/// through the piece's records.
///
/// # Errors
/// [`Halt`] from the read.
pub fn queue_moved(
    deliveries: &Deliveries,
    rec: &mut dyn Records,
    caller: &str,
    row: &TaskRow,
) -> Result<bool, Halt> {
    let config = local::held_config(rec, caller, &row.task_id)?;
    Ok(queue(deliveries, row, config.as_ref()))
}

/// File `owed` on the chains it names, for `caller`, stamped `now_s`; the writes go to `out`. One
/// that cannot be filed is dropped: a delivery's record is best-effort.
///
/// # Errors
/// [`Halt::Pending`] when a records call pends: the piece runs again with the same `owed`.
pub fn file_owed(
    rec: &mut dyn Records,
    caller: &str,
    owed: &[Owed],
    now_s: u64,
    out: &mut Vec<Write>,
) -> Result<(), Halt> {
    for o in owed.iter().filter(|o| o.caller == caller) {
        // No inbound request originates a delivery: the request id is empty.
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

/// One attempt in flight across its `tick` op's PENDING entries.
struct Flight {
    delivery: Delivery,
    exchange: Option<Exchange>,
}

/// The host calls one attempt makes, in their one order: the random byte (handle `0`), the judge
/// (handle `1`), the exchange (from handle `2`).
struct Calls<'h> {
    host: &'h StaticHost,
    services: StaticServices,
    ticket: Ticket,
}

impl Calls<'_> {
    const fn handle(&self, seq: u32) -> CompletionHandle {
        crate::task_door::handle(self.ticket, seq)
    }

    /// The jitter byte, from the kernel's random bytes.
    fn jitter(&self) -> u8 {
        let mut byte = [NO_JITTER];
        match self.services.random_fill(self.handle(0), &mut byte) {
            Ok(()) => byte[0],
            Err(_) => NO_JITTER,
        }
    }
}

/// WHAT ONE ATTEMPT ASKS OF THE HOST after its jitter byte, in its one order: the destination judge
/// over the callback, then the exchange. A seam, so what a verdict stops and what reaches the
/// receiver hold under a test's host as under the kernel's ([`attempt`]).
/// One judgement: the `DEST_*` verdict and the set a dial must land within.
type Judgement = (u64, String);

trait Line {
    /// The destination judge over `url`: its `DEST_*` verdict and the set a dial must land within;
    /// `None` when the host could not answer it (nothing was checked).
    fn judge(&mut self, url: &str) -> Poll<Option<Judgement>>;
    /// One exchange of `ex` to `url`: the receiver's status; `None` when the connection or the
    /// exchange failed.
    fn send(&mut self, ex: &mut Exchange, url: &str) -> Poll<Option<u16>>;
    /// The jitter byte of a retry's wait.
    fn jitter(&mut self) -> u8;
    /// GIVE UP the connection of an attempt abandoned at its timeout: the host closes `stream` (when
    /// the attempt had established one), so nothing the far end answers later reaches anyone.
    fn abandon(&mut self, stream: Option<u64>);
}

impl Line for Calls<'_> {
    fn jitter(&mut self) -> u8 {
        Calls::jitter(self)
    }

    fn abandon(&mut self, stream: Option<u64>) {
        if let Some(stream) = stream {
            // The close names the stream itself, so it needs nothing the tick's cycle forgot; it
            // never pends on a table, and a close that fails leaves nothing more to do.
            let _ = self.host.connector_from(self.ticket, 2).close(stream);
        }
    }
    fn judge(&mut self, url: &str) -> Poll<Option<Judgement>> {
        match crate::task_door::judge_open_web(&self.services, self.handle(1), url) {
            // More addresses than the first call had room for: re-called ONCE, on the same
            // handle, at the size the host named (the service's short-buffer rule).
            Poll::Ready(Err(ServiceError::Short { bytes, items })) => {
                let size = |n: u64| usize::try_from(n).unwrap_or(usize::MAX);
                crate::task_door::judge_open_web_sized(
                    &self.services,
                    self.handle(1),
                    url,
                    size(bytes),
                    size(items),
                )
                .map(Result::ok)
            }
            answered => answered.map(Result::ok),
        }
    }

    fn send(&mut self, ex: &mut Exchange, url: &str) -> Poll<Option<u16>> {
        let mut conn = self.host.connector_from(self.ticket, 2);
        match exchange(&mut conn, ex, NEED_OPEN_WEB, Some(url)) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(reply)) => Poll::Ready(Some(reply.status)),
            Poll::Ready(Err(_)) => Poll::Ready(None),
        }
    }
}

/// One attempt of `flight` over `line`: its end once known. The destination is judged afresh on
/// EVERY attempt (spec l.392-393, "re-runs the destination judge on every attempt"), and the dial
/// lands only within what that judgement admitted: a refusal ends the attempt before anything is
/// framed or sent.
fn attempt(line: &mut dyn Line, flight: &mut Flight) -> Poll<Attempted> {
    let url = flight.delivery.url.clone();
    let (verdict, within) = match line.judge(&url) {
        Poll::Pending => return Poll::Pending,
        // Nothing was checked, so nothing is sent; the host's judge failing is no refusal of the
        // destination, so the attempt ends as a transport error, retried under the three-attempt
        // rule.
        Poll::Ready(None) => return Poll::Ready(Attempted::Transport),
        Poll::Ready(Some(judged)) => judged,
    };
    if verdict != DEST_ALLOWED {
        return Poll::Ready(Attempted::Judged(verdict));
    }
    // The credential joins the request only now, after the judge has passed.
    if flight.exchange.is_none() {
        let (request, sealed) = crate::push::request(&flight.delivery);
        match Exchange::request_sealed(request, sealed) {
            Ok(ex) => flight.exchange = Some(ex.landing_within(within)),
            // A request busbar cannot frame sends nothing.
            Err(_) => return Poll::Ready(Attempted::Judged(DEST_UNRESOLVABLE)),
        }
    }
    let Some(ex) = flight.exchange.as_mut() else {
        return Poll::Ready(Attempted::Transport);
    };
    match line.send(ex, &url) {
        Poll::Pending => Poll::Pending,
        Poll::Ready(Some(status)) => Poll::Ready(Attempted::of_status(status)),
        Poll::Ready(None) => Poll::Ready(Attempted::Transport),
    }
}

/// THE ATTEMPT IN FLIGHT, held in plane memory with the clock of the tick that began it: the
/// instance has one driver ticket, so at most one delivery is attempted at a time. A tick that
/// pends ends there (a driver ticket's op is never resumed: `abi::mechanism::lifecycle`, the
/// dispatcher's driver-ticket note), so what pended goes on through `drive` ([`drive`]).
#[derive(Default)]
pub(crate) struct Attempting(Keyed<(), (Flight, u64)>);

impl Attempting {
    fn take(&self) -> Option<(Flight, u64)> {
        self.0.remove(&())
    }

    /// When the held attempt began (the clock of the tick that started it).
    fn started_ns(&self) -> Option<u64> {
        self.0.with(&(), |h| h.map(|(_, at)| *at))
    }

    /// When the held attempt is abandoned; `0` = none is held.
    pub(crate) fn deadline_ns(&self) -> u64 {
        self.started_ns()
            .map_or(0, |at| at.saturating_add(DELIVERY_TIMEOUT_NS).max(1))
    }

    fn hold(&self, flight: Flight, now_ns: u64) {
        self.0.insert((), (flight, now_ns));
    }
}

/// The time a whole delivery attempt may take, from the tick that began it: judge, open, write and
/// response together, [`crate::push::ATTEMPT_TIMEOUT_MS`], ten seconds. An attempt
/// still held then is abandoned, its connection closed, and settles as a transport error under the
/// three-attempt rule.
const DELIVERY_TIMEOUT_NS: u64 = crate::push::ATTEMPT_TIMEOUT_MS * 1_000_000;

/// When the lifecycle tick is next wanted: while an attempt is held, ONLY the moment it is
/// abandoned; else the earliest waiting delivery; `0` = neither. A held attempt's tick starts no
/// other attempt and its start forgets the held exchange's answers (a tick is the driver ticket's
/// cycle boundary, [`Deliveries::wake`]), so a delivery due meanwhile asks for no tick: the held
/// attempt's own completion wake (its `drive`, then the tick after it) attempts it.
pub(crate) fn next_tick_ns(deliveries: &Deliveries, attempting: &Attempting) -> u64 {
    match attempting.deadline_ns() {
        0 => deliveries.next_tick_ns(),
        deadline => deadline,
    }
}

/// `tick`: ONE due notification attempted (see the module note); PENDING while its exchange is,
/// which ends the tick and leaves the attempt to `drive`. While an attempt is held the tick starts
/// no other and makes no host call: the delivery's one request is the held attempt's, and it goes
/// on only through `drive`, so a delivery is never sent by both paths. A door opened without host
/// tables, or a tick that may not pend, attempts nothing.
pub(crate) fn tick_deliveries(
    plane: &A2aDoor,
    instance: &Instance<'_, A2aDoor>,
    now_ns: u64,
) -> Outcome {
    let Some((_, mut calls)) = calls_of(plane, instance) else {
        return Outcome::Ready;
    };
    arm(plane, instance);
    tick_over(&mut calls, &plane.deliveries, &plane.attempting, now_ns)
}

/// ARM the wake of the instance's driver ticket, the one a `tick` runs on, once: a queued
/// delivery wakes it ([`Deliveries::wake`]). Every tick arms it, so the first tick after `open`
/// does whatever else it does first.
pub(crate) fn arm(plane: &A2aDoor, instance: &Instance<'_, A2aDoor>) {
    let ticket = instance.ticket();
    if let (Some(host), false) = (plane.host, ticket.is_none()) {
        plane.deliveries.arm(|| Box::new(move || host.wake(ticket)));
    }
}

/// `drive`: the attempt a `tick` left PENDING goes on, the wake on the driver ticket being its
/// service's (the replay rule: the same host calls in the same order, each completed one answered
/// as it was). With no attempt in flight there is nothing to do.
pub(crate) fn drive(plane: &A2aDoor, instance: &Instance<'_, A2aDoor>) -> Outcome {
    match calls_of(plane, instance) {
        Some((_, mut calls)) => drive_over(&mut calls, &plane.deliveries, &plane.attempting),
        None => Outcome::Ready,
    }
}

/// The driver ticket this op runs on and the host calls it makes, when the door has the host it
/// needs to attempt a delivery.
fn calls_of<'p>(
    plane: &'p A2aDoor,
    instance: &Instance<'_, A2aDoor>,
) -> Option<(Ticket, Calls<'p>)> {
    let (host, services) = (plane.host.as_ref()?, plane.services?);
    let ticket = instance.ticket();
    (!ticket.is_none()).then_some((
        ticket,
        Calls {
            host,
            services,
            ticket,
        },
    ))
}

/// [`tick_deliveries`] over `line`.
fn tick_over(
    line: &mut dyn Line,
    deliveries: &Deliveries,
    attempting: &Attempting,
    now_ns: u64,
) -> Outcome {
    // A retry whose attempt ended in `drive` waits from now, the tick after its end.
    deliveries.anchor(now_ns);
    if let Some(started) = attempting.started_ns() {
        // A held attempt belongs to `drive`, until it outlives its timeout (its wake was lost):
        // then it is CANCELLED FIRST (its connection closed, so it can never also complete), and
        // only then requeued under the retry rules, so two attempts for one delivery are never in
        // flight at once.
        if now_ns >= started.saturating_add(DELIVERY_TIMEOUT_NS) {
            if let Some((flight, _)) = attempting.take() {
                deliveries.holding(false);
                line.abandon(flight.exchange.as_ref().and_then(Exchange::stream));
                let jitter = line.jitter();
                deliveries.owe(&flight.delivery, Attempted::Transport);
                let _ = deliveries.settle(
                    &flight.delivery.task_id,
                    Attempted::Transport,
                    now_ns,
                    jitter,
                );
            }
        }
        return Outcome::Ready;
    }
    match deliveries.next_due(now_ns) {
        Some(delivery) => advance_attempt(
            line,
            deliveries,
            attempting,
            Flight {
                delivery,
                exchange: None,
            },
            now_ns,
            Some(now_ns),
        ),
        None => Outcome::Ready,
    }
}

/// [`drive`] over `line`.
fn drive_over(line: &mut dyn Line, deliveries: &Deliveries, attempting: &Attempting) -> Outcome {
    match attempting.take() {
        Some((flight, started_ns)) => {
            advance_attempt(line, deliveries, attempting, flight, started_ns, None)
        }
        None => Outcome::Ready,
    }
}

/// One entry of `flight`'s attempt, begun at `started_ns`: held again while its exchange pends,
/// else settled. A retry's wait counts from when the attempt ENDED (spec l.391-392, two delays of
/// 250/500 ms): `now_ns` on a `tick`; a `drive` reads no clock (`None`), so its wait is counted by
/// the tick the wake is followed by, and the driver ticket is woken for it.
fn advance_attempt(
    line: &mut dyn Line,
    deliveries: &Deliveries,
    attempting: &Attempting,
    mut flight: Flight,
    started_ns: u64,
    now_ns: Option<u64>,
) -> Outcome {
    let jitter = line.jitter();
    match attempt(line, &mut flight) {
        Poll::Pending => {
            attempting.hold(flight, started_ns);
            deliveries.holding(true);
            Outcome::Pending
        }
        Poll::Ready(end) => {
            deliveries.holding(false);
            deliveries.owe(&flight.delivery, end);
            let task_id = &flight.delivery.task_id;
            match now_ns {
                Some(now_ns) => {
                    let _ = deliveries.settle(task_id, end, now_ns, jitter);
                }
                None => {
                    if let DeliverySettled::Retry(_) = deliveries.settle_ended(task_id, end, jitter)
                    {
                        deliveries.wake();
                    }
                }
            }
            Outcome::Ready
        }
    }
}

#[cfg(test)]
#[path = "tests/push_door_tests.rs"]
mod tests;
