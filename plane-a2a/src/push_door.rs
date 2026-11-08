// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Push delivery, driven by the door: the host's half of [`crate::push`].
//!
//! * A relayed task that MOVES queues its notification ([`queue`]): to the push_config host record
//!   the caller registered through CRUD or inline. A legacy row URL alone supplies no credential
//!   authority, so a task with no durable config queues nothing.
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

type StaticHost = KindStaticHost<busbar_contract::plugin::markers::PlaneKind>;

type StaticServices = KindStaticServices<busbar_contract::plugin::markers::PlaneKind>;

use std::task::Poll;

use busbar_contract::abi::host::service::DEST_ALLOWED;
use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::mechanism::ticket::{CompletionHandle, Ticket};
use busbar_contract::abi::sdk::conn::Host as KindStaticHost;
use busbar_contract::abi::sdk::exchange::{exchange, Exchange};
use busbar_contract::abi::sdk::publish::Keyed;
use busbar_contract::abi::sdk::{Instance, ServiceError, Services as KindStaticServices};

use crate::a2a::task::Task;
use crate::local::{self, PushConfig};
use crate::plane_door::A2aDoor;
use crate::push::{Attempted, Deliveries, Delivery, Tokens};
use crate::statement::NEED_OPEN_WEB;
use crate::tasks::{self, Halt, Stamp};
use crate::TaskRow;

/// The jitter byte that moves a retry's wait by nothing: used when the host lends no random byte
/// (a delay is a timing nicety, not a security property).
const NO_JITTER: u8 = 128;

/// The notification `row`'s move owes, to `config` (the push_config record of the task) with that
/// config's credential taken now with its URL; `None` without a durable config.
pub(crate) fn captured(row: &TaskRow, config: Option<&PushConfig>) -> Option<Delivery> {
    let mut task = match Task::from_row(row) {
        Ok(task) => task,
        Err(_) => {
            busbar_contract::diag_warn!(
                crate::diagnostics::A2A_PUSH_CHECK_UNAVAILABLE,
                "a2a: malformed task notification cannot be rendered"
            );
            return None;
        }
    };
    let Some(cfg) = config else {
        if task.push_callback.is_some() {
            busbar_contract::diag_warn!(
                crate::diagnostics::A2A_PUSH_CHECK_UNAVAILABLE,
                "a2a: legacy callback has no durable config; notification refused"
            );
        }
        return None;
    };
    if let Some(callback) = &mut task.push_callback {
        crate::request_json::wipe_string(callback);
    }
    task.push_callback = Some(cfg.url.clone());
    task.push_version.clone_from(&cfg.version);
    let mut delivery = Delivery::of(&task)?;
    delivery.auth = cfg.authentication.clone();
    delivery.from_config = true;
    Some(delivery)
}

/// RELEASE busbar's own callback token for `row`'s task once the move has ENDED it, whichever way
/// it ended, so an ended task's token does not count against [`crate::push::MAX_TOKENS`].
pub fn ended(tokens: &Tokens, row: &TaskRow) {
    if Task::from_row(row).is_ok_and(|t| t.state.is_terminal()) {
        tokens.forget(&row.task_id);
    }
}

/// Apply only metadata from exact Applied receipts, outside the Journal and Book guards.
pub(crate) fn apply_publication(
    plane: &A2aDoor,
    journal: &crate::conditional_publication::Journal,
) {
    let effects = plane.deliveries.apply_publication(journal);
    let owner = effects.owner;
    for (row, _) in effects.notify {
        ended(&plane.tokens, &row);
    }
    for (row, backend) in effects.backends {
        plane.remember_backend(&row, backend);
    }
    for receipt in effects.owed {
        plane.deliveries.acknowledge_owed(&receipt);
    }
    for receipt in effects.release_owed {
        plane.deliveries.release_owed(&receipt);
    }
    journal.effects_finished(owner);
}

/// An outcome-only driver crossing never resumes a canceled callback or lends a new candidate.
pub(crate) fn settle_publications<T: busbar_contract::abi::sdk::door::AbiOut>(
    plane: &A2aDoor,
    ticket: Ticket,
    extensions: &[u8],
    out: &mut busbar_contract::abi::sdk::Out<'_, T>,
) -> Option<Outcome> {
    use busbar_contract::abi::sdk::plane::conditional as wire;

    match wire::read_capability(extensions) {
        Ok(Some(capability)) if capability.ticket == ticket => {}
        Ok(None) => return None,
        _ => return Some(Outcome::Failed),
    };
    let incoming = match wire::read_settlement(extensions) {
        Ok(incoming) => incoming,
        Err(_) => return Some(Outcome::Failed),
    };
    let journals = plane.deliveries.publications();
    for journal in &journals {
        if journal.ack_confirmed(incoming.as_ref()) {
            plane.deliveries.release_publication(journal);
        }
    }
    if let Some(settlement) = incoming {
        for journal in journals {
            match journal.settle(&settlement) {
                Err(_) => return Some(Outcome::Failed),
                Ok(false) => continue,
                Ok(true) => {
                    apply_publication(plane, &journal);
                    if !journal.effects_complete() {
                        return Some(Outcome::Pending);
                    }
                    if out
                        .conditional_settlement_ack(&plane.publication_leases, &settlement)
                        .is_err()
                    {
                        return Some(Outcome::Failed);
                    }
                    journal.offer_ack(&settlement);
                    return Some(Outcome::Pending);
                }
            }
        }

        return Some(Outcome::Failed);
    }
    for journal in journals {
        if journal.is_cancelled() {
            apply_publication(plane, &journal);
            if journal.cancelled_without_receipt() {
                plane.deliveries.release_publication(&journal);
            }
        }
    }
    None
}

pub(crate) fn deferred(row: &TaskRow) -> Delivery {
    Delivery {
        task_id: row.task_id.clone(),
        caller: row.principal.clone(),
        url: String::new(),
        body: Vec::new(),
        terminal: false,
        auth: None,
        from_config: true,
        unresolved: Some(Box::new(row.clone())),
    }
}

/// The callback's conditional filing keeps ownership in the delivery book until each exact
/// outcome's event applied. A later pending outcome or cancellation cannot lose an earlier one.
pub(crate) fn file_owed_committed(
    via: &mut crate::task_door::Via<'_>,
    journal: &crate::conditional_publication::Journal,
    deliveries: &Deliveries,
    caller: &str,
    owed: &[crate::push::OwedReceipt],
    now_s: u64,
) -> Result<(), Halt> {
    for receipt in owed.iter().filter(|r| r.outcome.caller == caller) {
        via.effects(crate::conditional_publication::Draft {
            owed: Some(receipt.clone()),
            ..Default::default()
        });
        let o = &receipt.outcome;
        let at = Stamp {
            caller,
            request_id: "",
            now: now_s,
        };
        tasks::record_push_delivery(via, &at, &o.task_id, o.kind, &mut Vec::new())?;
        match journal.owed_decision(receipt) {
            Some(true) => {
                deliveries.acknowledge_owed(receipt);
                journal.owed_done(receipt);
            }
            Some(false) => deliveries.release_owed(receipt),
            None => {}
        }
    }
    Ok(())
}

/// One attempt in flight across its `tick` op's PENDING entries.
struct Flight {
    delivery: Delivery,
    exchange: Option<Exchange>,
    /// Replayed on every pending entry so all following service handles keep their sequence.
    config_read: Option<Box<TaskRow>>,
}

/// The host calls one attempt makes, in their one order: the random byte (handle `0`), the judge
/// (handle `1`), the exchange (from handle `2`).
struct Calls<'h> {
    host: &'h StaticHost,
    services: StaticServices,
    ticket: Ticket,
    grown: &'h crate::task_door::Grown,
    base: u32,
}

impl Calls<'_> {
    const fn handle(&self, seq: u32) -> CompletionHandle {
        crate::task_door::handle(self.ticket, self.base + seq)
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

/// One judgement: the `DEST_*` verdict and the set a dial must land within.
type Judgement = (u64, String);

trait Line {
    fn config(&mut self, _row: &TaskRow) -> Result<Option<PushConfig>, Halt> {
        Err(Halt::Failed("config service unavailable".into()))
    }
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
    fn config(&mut self, row: &TaskRow) -> Result<Option<PushConfig>, Halt> {
        let mut via =
            crate::task_door::Via::new(self.host, Some(self.services), self.ticket, 0, self.grown);
        let config = local::held_config(&mut via, &row.principal, &row.task_id);
        self.base = via.issued();
        config
    }
    fn jitter(&mut self) -> u8 {
        Calls::jitter(self)
    }

    fn abandon(&mut self, stream: Option<u64>) {
        if let Some(stream) = stream {
            let _ = self
                .host
                .connector_from(self.ticket, self.base + 2)
                .close(stream);
        }
    }
    fn judge(&mut self, url: &str) -> Poll<Option<Judgement>> {
        match crate::task_door::judge_open_web(&self.services, self.handle(1), url) {
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
        let mut conn = self.host.connector_from(self.ticket, self.base + 2);
        match exchange(&mut conn, ex, NEED_OPEN_WEB, Some(url)) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(reply)) => Poll::Ready(Some(reply.status)),
            Poll::Ready(Err(_)) => Poll::Ready(None),
        }
    }
}

/// One attempt of `flight` over `line`: its end once known. The destination is judged afresh on
/// every attempt, and a refusal ends the attempt before anything is framed or sent.
fn attempt(line: &mut dyn Line, deliveries: &Deliveries, flight: &mut Flight) -> Poll<Attempted> {
    let url = crate::proto::custody::Guard::new(flight.delivery.url.clone());
    let (verdict, within) = match line.judge(&url) {
        Poll::Pending => return Poll::Pending,

        Poll::Ready(None) => return Poll::Ready(Attempted::Transport),
        Poll::Ready(Some(judged)) => judged,
    };
    if verdict != DEST_ALLOWED {
        return Poll::Ready(Attempted::Judged(verdict));
    }

    if flight.exchange.is_none() {
        let (request, sealed) = deliveries.request(&flight.delivery);
        match Exchange::request_sealed(request, sealed) {
            Ok(ex) => flight.exchange = Some(ex.landing_within(within)),

            Err(_) => {
                busbar_contract::diag_warn!(
                    crate::diagnostics::A2A_PUSH_CHECK_UNAVAILABLE,
                    "a2a: push request could not be prepared"
                );
                return Poll::Ready(Attempted::Transport);
            }
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

/// The time a whole delivery attempt may take, from the tick that began it (judge, open, write and
/// response together), after which a held attempt is abandoned and settles as a transport error.
const DELIVERY_TIMEOUT_NS: u64 = crate::push::ATTEMPT_TIMEOUT_MS * 1_000_000;

/// When the lifecycle tick is next wanted: while an attempt is held, ONLY the moment it is
/// abandoned; else the earliest waiting delivery; `0` = neither.
pub(crate) fn next_tick_ns(deliveries: &Deliveries, attempting: &Attempting) -> u64 {
    match attempting.deadline_ns() {
        0 => deliveries.next_tick_ns(),
        deadline => deadline,
    }
}

/// `tick`: ONE due notification attempted, PENDING while its exchange is (the attempt then goes on
/// only through `drive`); while an attempt is held the tick starts no other.
pub(crate) fn tick_deliveries(
    plane: &A2aDoor,
    instance: &Instance<'_, A2aDoor, busbar_contract::plugin::markers::PlaneKind>,
    now_ns: u64,
) -> Outcome {
    let Some((_, mut calls)) = calls_of(plane, instance) else {
        return Outcome::Ready;
    };
    arm(plane, instance);
    tick_over(&mut calls, &plane.deliveries, &plane.attempting, now_ns)
}

/// ARM the wake of the instance's driver ticket, the one a `tick` runs on, once: a queued
/// delivery wakes it ([`Deliveries::wake`]).
pub(crate) fn arm(
    plane: &A2aDoor,
    instance: &Instance<'_, A2aDoor, busbar_contract::plugin::markers::PlaneKind>,
) {
    let ticket = instance.ticket();
    if let (Some(host), false) = (plane.host, ticket.is_none()) {
        plane.deliveries.arm(|| Box::new(move || host.wake(ticket)));
    }
}

/// `drive`: the attempt a `tick` left PENDING goes on, the wake on the driver ticket being its
/// service's; with no attempt in flight there is nothing to do.
pub(crate) fn drive(
    plane: &A2aDoor,
    instance: &Instance<'_, A2aDoor, busbar_contract::plugin::markers::PlaneKind>,
) -> Outcome {
    match calls_of(plane, instance) {
        Some((_, mut calls)) => drive_over(&mut calls, &plane.deliveries, &plane.attempting),
        None => Outcome::Ready,
    }
}

/// The driver ticket this op runs on and the host calls it makes, when the door has the host it
/// needs to attempt a delivery.
fn calls_of<'p>(
    plane: &'p A2aDoor,
    instance: &Instance<'_, A2aDoor, busbar_contract::plugin::markers::PlaneKind>,
) -> Option<(Ticket, Calls<'p>)> {
    let (host, services) = (plane.host.as_ref()?, plane.services?);
    let ticket = instance.ticket();
    (!ticket.is_none()).then_some((
        ticket,
        Calls {
            host,
            services,
            ticket,
            grown: &plane.grown,
            base: 0,
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
    deliveries.anchor(now_ns);
    if let Some(started) = attempting.started_ns() {
        if now_ns >= started.saturating_add(DELIVERY_TIMEOUT_NS) {
            if let Some((flight, _)) = attempting.take() {
                deliveries.holding(false);
                deliveries.wake();
                line.abandon(flight.exchange.as_ref().and_then(Exchange::stream));
                if !deliveries.current(&flight.delivery) {
                    return Outcome::Ready;
                }
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
                config_read: delivery.unresolved.clone(),
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
/// else settled, a retry's wait counted from `now_ns` (or, on `drive`, from the following tick).
fn advance_attempt(
    line: &mut dyn Line,
    deliveries: &Deliveries,
    attempting: &Attempting,
    mut flight: Flight,
    started_ns: u64,
    now_ns: Option<u64>,
) -> Outcome {
    if !deliveries.current(&flight.delivery) {
        deliveries.holding(false);
        deliveries.wake();
        line.abandon(flight.exchange.as_ref().and_then(Exchange::stream));
        return Outcome::Ready;
    }
    if let Some(row) = flight.config_read.as_deref() {
        match line.config(row) {
            Err(Halt::Pending) => {
                attempting.hold(flight, started_ns);
                deliveries.holding(true);
                return Outcome::Pending;
            }
            Err(Halt::Failed(_)) => {
                let jitter = line.jitter();
                deliveries.holding(false);
                deliveries.wake();
                deliveries.owe(&flight.delivery, Attempted::Transport);
                match now_ns {
                    Some(now) => {
                        deliveries.settle(
                            &flight.delivery.task_id,
                            Attempted::Transport,
                            now,
                            jitter,
                        );
                    }
                    None => {
                        deliveries.settle_ended(
                            &flight.delivery.task_id,
                            Attempted::Transport,
                            jitter,
                        );
                        deliveries.wake();
                    }
                }
                return Outcome::Ready;
            }
            Ok(config) if flight.delivery.unresolved.is_some() => {
                let resolved = captured(row, config.as_ref());
                if let Some(resolved) = resolved {
                    if !deliveries.resolve(&flight.delivery, resolved.clone()) {
                        deliveries.holding(false);
                        deliveries.wake();
                        return Outcome::Ready;
                    }
                    flight.delivery = resolved;
                } else {
                    deliveries.discard(&flight.delivery);
                    deliveries.holding(false);
                    deliveries.wake();
                    return Outcome::Ready;
                }
            }
            Ok(_) => {}
        }
    }
    let jitter = line.jitter();
    match attempt(line, deliveries, &mut flight) {
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
                    deliveries.settle_ended(task_id, end, jitter);
                    deliveries.wake();
                }
            }
            Outcome::Ready
        }
    }
}

#[cfg(test)]
#[path = "tests/push_door_tests.rs"]
pub(crate) mod tests;
