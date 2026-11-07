// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE A2A PLANE'S ROOT LEG, through its door: the agent plane's root cells are units driven on the
//! composition root's door path: the door linked and bound through the loader's one load.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::http::StatusCode;
use busbar_contract::abi::mechanism::door::DoorFn;
use busbar_kernel::governance::signing::{TokenSigner, DEFAULT_KID};
use busbar_kernel::governance::{GovState, NewKeySpec};
use busbar_kernel::{
    plane_driver::{EndPost, PlaneMoney},
    plane_routes::ListenerScheme,
};

/// The plane's private facts and the protobuf words this leg sends and reads, restated as data
/// (the crate's unit test `door_facts` holds each to the item it restates).
#[path = "../support/root_facts.rs"]
#[allow(dead_code)]
mod root_facts;

mod binding_lifetime;
mod bootstrap;
mod conditional_quota_negotiation;
mod reported_observations;

use crate::root::loader::dispatch::{
    kinds::plane::Plane, load_dropped, load_linked, rendering_of_library, Bind, ConnTable,
    DispatchConfig, Dispatcher, LinkedRow, NoSink,
};
use crate::root::plane_node::{Node, NodeEndPost};
use crate::root::PUBLISHING;

/// Keep actual host and plugin refusals visible when a root fixture fails.
struct FixtureDiagnostics;

impl crate::root::loader::dispatch::EnvelopeSink for FixtureDiagnostics {
    fn metric(&self, _: crate::root::loader::dispatch::Metric<'_>) {}

    fn diag(&self, diagnostic: crate::root::loader::dispatch::Diagnostic<'_>) {
        eprintln!("A2A fixture diagnostic: {diagnostic:?}");
    }

    fn dropped(&self, why: crate::root::loader::dispatch::Dropped) {
        eprintln!("A2A fixture dropped diagnostic: {why:?}");
    }

    fn refused(&self, instance: &str, why: crate::root::loader::observe::BindRefusal<'_>) {
        eprintln!("A2A fixture {instance} refused: {why:?}");
    }
}

/// The deployment's dated card history, billing off (one entry, no price).
static CARD: std::sync::LazyLock<crate::root::kernel::RootHistory> =
    std::sync::LazyLock::new(|| {
        let history = crate::root::kernel::RootHistory::default();
        history.apply(
            crate::root::kernel::card_from_config(
                std::iter::empty::<(&str, busbar_contract::billing::RawTierRates)>(),
                0,
                true,
            ),
            1_000,
        );
        history
    });

/// The governance book's admin token.
const ADMIN_TOKEN: &str = "admintok";

/// The plane's wire words its Statement does not carry, as DATA
/// (`tests/fixtures/agent_door_wire.txt`): one `key = value` per line, `#` a comment.
fn surface(key: &str) -> &'static str {
    include_str!("fixtures/agent_door_wire.txt")
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .find_map(|l| {
            let (k, v) = l.split_once('=')?;
            (k.trim() == key).then(|| v.trim())
        })
        .unwrap_or_else(|| panic!("fixtures/agent_door_wire.txt has no `{key}` row"))
}

/// The mount the door's claims sit under.
fn mount() -> &'static str {
    surface("mount")
}

/// THE AGENT DOOR: of the linked plane doors, the one whose Statement DECLARES the section the
/// fixture names (found by binding each, once).
fn linked_door() -> Option<DoorFn> {
    Some(busbar_plane_a2a::door)
}

/// The agent door, which a cell's `Served` needs (see [`linked_door`]).
fn door() -> DoorFn {
    linked_door().expect("a linked plane door owns the agents section")
}

/// THIS PLANE'S CAPABILITY-EQUALITY COLUMNS (`qa/capability-equality.json`): the cells its root leg
/// answers for.
pub(crate) const COLUMNS: &[&str] = &["a2a-client", "a2a-server"];

/// `(capability, column, reason)`: the root-leg cells this plane is NOT owed, each the ledger's own
/// not-applicable cell with its reason, word for word.
pub(crate) const NOT_APPLICABLE: &[(&str, &str, &str)] = &[
    (
        "breaker-trip",
        "a2a-server",
        "the front door is inbound; there is no upstream target whose availability could be recorded on this role. The agent a hop dials is the a2a-client cell's evidence.",
    ),
    (
        "breaker-fastfail",
        "a2a-server",
        "inbound role; there is no dispatch admission against an upstream to make fast. Refusing inbound work is the governance and trust cells' subject, not the breaker's.",
    ),
    (
        "failover-reroute",
        "a2a-server",
        "inbound role; there is no candidate set to walk on the receiving side. The relay's candidate walk is the a2a-client cell.",
    ),
    (
        "hooks-gate",
        "a2a-client",
        "busbar-originated A2A traffic is not a second gate point: originate (mirror_push_config, refresh_listed_tasks) is called only from receive.rs::admitted, downstream of the proven inbound hooks gate, and push delivery targets the caller's own webhook, which the agent-submission gate has no semantic target for. Same rationale the other outbound client cells are proven under.",
    ),
    (
        "disposition",
        "a2a-server",
        "disposition classifies an upstream's ANSWER; the inbound role has no upstream answer to classify. Rendering a refusal to a caller is the response path, not disposition.",
    ),
];

/// THE SECRET-SOURCE SCAN'S DRIVEN DOOR (the composition root's `secret_source.rs`, which holds
/// every linked door plane to a driver): this door's Statement name.
pub(crate) fn secret_source_driven() -> Vec<String> {
    let row = LinkedRow::of(door()).expect("the door states itself");
    vec![
        busbar_contract::abi::mechanism::rendering::read(&row.statement)
            .expect("its Statement reads")
            .name,
    ]
}

/// RFC 8785 for the cells' own cards (strings, small integers, objects, arrays): keys sorted,
/// compact, as the plane canonicalizes a card it signs or pins.
fn canonical(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let members: Vec<String> = keys
                .into_iter()
                .map(|k| {
                    format!(
                        "{}:{}",
                        serde_json::Value::String(k.clone()),
                        canonical(&map[k])
                    )
                })
                .collect();
            format!("{{{}}}", members.join(","))
        }
        serde_json::Value::Array(items) => {
            format!(
                "[{}]",
                items.iter().map(canonical).collect::<Vec<_>>().join(",")
            )
        }
        other => other.to_string(),
    }
}

/// These fixture cards' JWS payload, independently of the plane's implementation.
/// A2A v1.0 §8.4.1/§8.4.3 require proto-default removal before JCS. The only implicit
/// default in these cards is SecurityRequirement.schemes.*.list: an empty repeated
/// string field. Keep its containing map entry (a present message), required empty
/// capabilities, and all other content; v0.3 has no such default-removal rule.
fn signing_payload(card: &serde_json::Value) -> String {
    let mut stripped = card.clone();
    if let Some(obj) = stripped.as_object_mut() {
        obj.remove("signatures");
    }
    if card
        .get("supportedInterfaces")
        .is_some_and(serde_json::Value::is_array)
    {
        if let Some(requirements) = stripped
            .get_mut("securityRequirements")
            .and_then(serde_json::Value::as_array_mut)
        {
            for requirement in requirements {
                if let Some(schemes) = requirement
                    .get_mut("schemes")
                    .and_then(serde_json::Value::as_object_mut)
                {
                    for scopes in schemes.values_mut() {
                        if scopes
                            .get("list")
                            .and_then(serde_json::Value::as_array)
                            .is_some_and(Vec::is_empty)
                        {
                            scopes.as_object_mut().expect("StringList").remove("list");
                        }
                    }
                }
            }
        }
    }
    canonical(&stripped)
}

/// A card's pinned fingerprint: the tagged sha256 of the canonical whole card.
fn card_fingerprint(card: &serde_json::Value) -> String {
    busbar_contract::abi::sdk::digest::sha256_tagged(canonical(card).as_bytes())
}

/// One a2a door served on a data router, as production composes it, and the admin router the
/// door's stated admin routes mount on.
struct Served {
    kernel: Arc<busbar_kernel::host_services::KernelServices>,
    router: axum::Router,
    admin: axum::Router,
    gov: Arc<GovState>,
    app: Arc<busbar_kernel::state::App>,
    key: busbar_contract::records::VirtualKey,
    token: String,
    /// The handle a config apply swaps the serving generation on.
    handle: Arc<busbar_kernel::state::AppHandle>,
    /// The node's book: every unit's one line.
    book: Arc<std::sync::Mutex<crate::root::durability::Durability>>,
    /// The node's end post: the units whose facts are still open.
    post: Arc<NodeEndPost>,
    /// The paths the door's routes were mounted at on the data router, as its construction
    /// was handed them.
    routes: Vec<String>,
    /// The bytes a record key must hold for the cell's store to refuse writing it
    /// ([`Refusing`]); `None` = the store takes every write.
    refuse: Arc<std::sync::Mutex<Option<Vec<u8>>>>,
    /// The table the kernel's egress walk reached the far ends through, every open it made on it
    /// recorded ([`Riding`]).
    riding: Arc<Riding>,
    observed_destinations: Arc<reported_observations::Destinations>,
    deployment: serde_json::Value,
    plugins: busbar_kernel::config::PluginsCfg,
    rules: Arc<dyn busbar_kernel::appbuild::RootRules>,
    /// Retain the actual root appliers for generation-lifetime regression controls.
    appliers: crate::root::serve::DoorAppliers,
    hook_peers: Vec<tokio::task::JoinHandle<()>>,
}

impl Drop for Served {
    fn drop(&mut self) {
        for peer in &self.hook_peers {
            peer.abort();
        }
    }
}

impl Served {
    /// A reload uses the same production builder and its prior generation, including Store and
    /// governance. Pool ownership can be installed independently of a raw door section.
    fn applied(
        &self,
        section: serde_yaml::Value,
        keep_pools: bool,
    ) -> Arc<busbar_kernel::state::App> {
        let mut deployment = self.deployment.clone();
        deployment[surface("section")] =
            serde_json::to_value(section).expect("the applied section");
        let deploy = busbar_kernel::config::deploy_from_deserializer(deployment)
            .expect("the applied deployment parses");
        let mut config = busbar_kernel::config::resolve(&deploy, &Default::default())
            .expect("the applied deployment resolves");
        let prior = self.handle.load();
        if keep_pools {
            if let Some(pools) = prior.plane_pools(surface("plane_key")) {
                config.plane_pools.insert(surface("section"), pools.clone());
            }
        }
        let (next, rotate, limits) =
            futures::executor::block_on(crate::root::real_store::build_app(
                config,
                self.plugins.clone(),
                None,
                Default::default(),
                Default::default(),
                (None, None),
                Some(&prior),
                &self.rules,
            ))
            .expect("the normal root builds the applied generation");
        futures::executor::block_on(limits.keep()).expect("the applied card activates");
        if let Some(rotate) = rotate {
            futures::executor::block_on(rotate);
        }
        Arc::new(next)
    }
}

/// Inject storage failure at the native primitive boundary, preserving the host's
/// complete atomic candidate and receipt ownership.
struct Refusing {
    inner: Arc<dyn busbar_contract::persistence::PersistenceBackend>,
    named: Arc<std::sync::Mutex<Option<Vec<u8>>>>,
}
impl Refusing {
    fn refuses(&self, key: &[u8]) -> bool {
        self.named
            .lock()
            .expect("unpoisoned")
            .as_deref()
            .is_some_and(|n| n.is_empty() || key.windows(n.len()).any(|w| w == n))
    }
}
impl busbar_contract::persistence::PersistenceBackend for Refusing {
    fn info(&self) -> busbar_contract::persistence::BackendInfo {
        self.inner.info()
    }
    fn read(
        &self,
        request: Arc<busbar_contract::persistence::Read>,
    ) -> busbar_contract::persistence::Call<'_, busbar_contract::persistence::ReadResult> {
        self.inner.read(request)
    }
    fn scan(
        &self,
        request: Arc<busbar_contract::persistence::Scan>,
    ) -> busbar_contract::persistence::Call<'_, busbar_contract::persistence::Page> {
        self.inner.scan(request)
    }
    fn clock(
        &self,
        dataset: busbar_contract::persistence::DatasetId,
    ) -> busbar_contract::persistence::Call<'_, busbar_contract::persistence::ClockObservation>
    {
        self.inner.clock(dataset)
    }
    fn commit(
        &self,
        candidate: busbar_contract::persistence::PreparedCandidate,
    ) -> busbar_contract::persistence::Call<'_, busbar_contract::persistence::Decision> {
        use busbar_contract::persistence::{Failure, Mutation};
        if candidate.candidate().mutations.iter().any(|mutation| {
            let key = match mutation {
                Mutation::Put { address, .. } | Mutation::Delete(address) => &address.key,
                Mutation::DeleteRange { prefix, .. } => prefix,
            };
            self.refuses(key)
        }) {
            return Box::pin(async { Err(Failure::Refused) });
        }
        self.inner.commit(candidate)
    }
}

/// THE EGRESS WALK'S TABLE, WATCHED: the cell's connector as the kernel's walk reaches it (the
/// `conns` of the door's reach), every call the connector's own, and the `(owner, need)` of every
/// open the walk made recorded, so a cell reads which of the door's needs a hop rode.
struct Riding {
    inner: Arc<busbar_core_connector::Connector>,
    opened: std::sync::Mutex<
        Vec<(
            busbar_contract::conn::InstanceId,
            busbar_contract::conn::NeedId,
        )>,
    >,
}

impl Riding {
    /// Every `(owner, need)` the walk opened on, in order.
    fn opened(
        &self,
    ) -> Vec<(
        busbar_contract::conn::InstanceId,
        busbar_contract::conn::NeedId,
    )> {
        self.opened.lock().expect("the opens").clone()
    }
}

impl busbar_contract::conn::Conns for Riding {
    fn open(
        &self,
        caller: busbar_contract::conn::InstanceId,
        need: busbar_contract::conn::NeedId,
        desc: &busbar_contract::conn::OpenDesc<'_>,
    ) -> Result<busbar_contract::conn::ConnId, busbar_contract::conn::ConnError> {
        self.opened.lock().expect("the opens").push((caller, need));
        busbar_contract::conn::Conns::open(&*self.inner, caller, need, desc)
    }
    fn write(
        &self,
        caller: busbar_contract::conn::InstanceId,
        conn: busbar_contract::conn::ConnId,
        bytes: &[u8],
        end: bool,
        text: bool,
    ) -> Result<usize, busbar_contract::conn::ConnError> {
        busbar_contract::conn::Conns::write(&*self.inner, caller, conn, bytes, end, text)
    }
    fn read(
        &self,
        caller: busbar_contract::conn::InstanceId,
        conn: busbar_contract::conn::ConnId,
        ticket: busbar_contract::conn::Ticket,
        buf: &mut [u8],
    ) -> Result<busbar_contract::conn::Piece, busbar_contract::conn::ConnError> {
        busbar_contract::conn::Conns::read(&*self.inner, caller, conn, ticket, buf)
    }
    fn wait(
        &self,
        caller: busbar_contract::conn::InstanceId,
        set: &[busbar_contract::conn::ConnId],
        ticket: busbar_contract::conn::Ticket,
    ) -> Result<usize, busbar_contract::conn::ConnError> {
        busbar_contract::conn::Conns::wait(&*self.inner, caller, set, ticket)
    }
    fn facts(
        &self,
        caller: busbar_contract::conn::InstanceId,
        conn: busbar_contract::conn::ConnId,
    ) -> Result<busbar_contract::transport::ConnFacts, busbar_contract::conn::ConnError> {
        busbar_contract::conn::Conns::facts(&*self.inner, caller, conn)
    }
    fn close(
        &self,
        caller: busbar_contract::conn::InstanceId,
        conn: busbar_contract::conn::ConnId,
    ) -> Result<(), busbar_contract::conn::ConnError> {
        busbar_contract::conn::Conns::close(&*self.inner, caller, conn)
    }
}

impl busbar_contract::conn::PollConns for Riding {
    fn poll_read(
        &self,
        caller: busbar_contract::conn::InstanceId,
        conn: busbar_contract::conn::ConnId,
        cx: &mut std::task::Context<'_>,
        buf: &mut [u8],
    ) -> std::task::Poll<Result<busbar_contract::conn::Piece, busbar_contract::conn::ConnError>>
    {
        busbar_contract::conn::PollConns::poll_read(&*self.inner, caller, conn, cx, buf)
    }
    fn anchor(
        &self,
        owner: busbar_contract::conn::InstanceId,
        need: busbar_contract::conn::NeedId,
        member: &str,
        target: &str,
        anchors: &busbar_contract::transport::trust::Anchors,
    ) -> Result<(), busbar_contract::conn::ConnError> {
        busbar_contract::conn::PollConns::anchor(&*self.inner, owner, need, member, target, anchors)
    }
    fn seal_reach(
        &self,
        owner: busbar_contract::conn::InstanceId,
        need: busbar_contract::conn::NeedId,
        member: &str,
        target: &str,
        reach: bool,
    ) -> Result<(), busbar_contract::conn::ConnError> {
        busbar_contract::conn::PollConns::seal_reach(
            &*self.inner,
            owner,
            need,
            member,
            target,
            reach,
        )
    }
}

/// Which deployment the cell boots; the production builder derives its claims and admission.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Facing {
    /// The `agents:` section is written and its normal routes are exercised.
    Routes,
    /// The written section's normal audience and RFC 6750 metadata are also asserted.
    Admitted,
    /// No `agents:` section at all: the plane loads iff its section is present (LAW 7).
    Unconfigured,
}

/// The a2a door linked and bound through the loader's one load (its host services and the
/// process's connector): opened with `section` as its `agents:` section and a public base URL.
fn served(
    instance: &'static str,
    section: &str,
    block_loopback: bool,
    allowed_pools: Option<Vec<String>>,
) -> Served {
    served_trusting(instance, section, block_loopback, allowed_pools, None)
}

/// [`served`], its connector also trusting `root` (a test root's DER) beside the platform
/// roots, so a loopback TLS agent whose certificate it issued completes the chain check.
fn served_trusting(
    instance: &'static str,
    section: &str,
    block_loopback: bool,
    allowed_pools: Option<Vec<String>>,
    root: Option<Vec<u8>>,
) -> Served {
    served_under(
        instance,
        section,
        busbar_kernel::config::Destinations {
            block_private_addresses: true,
            blocked: if block_loopback {
                vec!["127.0.0.1".to_string()]
            } else {
                Vec::new()
            },
            ..Default::default()
        },
        allowed_pools,
        root,
    )
}

/// [`served`] under the deployment's destination settings `destinations`, its connector also
/// trusting `root` when given ([`served_trusting`]).
fn served_under(
    instance: &'static str,
    section: &str,
    destinations: busbar_kernel::config::Destinations,
    allowed_pools: Option<Vec<String>>,
    root: Option<Vec<u8>>,
) -> Served {
    served_full(
        instance,
        section,
        destinations,
        allowed_pools,
        root,
        None,
        None,
        Facing::Routes,
    )
}

/// [`served`] with the keyed caller bound to a group that admits `requests` requests in all.
fn served_limited(instance: &'static str, section: &str, requests: u64) -> Served {
    served_full(
        instance,
        section,
        busbar_kernel::config::Destinations {
            block_private_addresses: true,
            ..Default::default()
        },
        None,
        None,
        None,
        Some(requests),
        Facing::Routes,
    )
}

/// [`served`] facing the world as `facing` says, loopback admitted.
fn served_facing(instance: &'static str, section: &str, facing: Facing) -> Served {
    served_full(
        instance,
        section,
        busbar_kernel::config::Destinations {
            block_private_addresses: true,
            ..Default::default()
        },
        None,
        None,
        None,
        None,
        facing,
    )
}

/// The hooks the deployment attaches to one agent (`agents.<agent>.hooks:`): the loaded hook
/// plugin environment, the `hooks:` definitions, and the agent they attach to.
struct AgentHooks {
    defs: Vec<(String, serde_json::Value)>,
    agent: &'static str,
}

/// [`served_under`], the deployment's `hooks:` attached to one agent when `hooks` is given, the
/// door's hook stage bound as production binds it, and the keyed caller bound to a group admitting
/// `requests` requests in all when given.
#[allow(clippy::too_many_arguments)]
fn served_full(
    instance: &'static str,
    section: &str,
    destinations: busbar_kernel::config::Destinations,
    allowed_pools: Option<Vec<String>>,
    root: Option<Vec<u8>>,
    hooks: Option<AgentHooks>,
    requests: Option<u64>,
    facing: Facing,
) -> Served {
    served_core(
        instance,
        section,
        destinations,
        allowed_pools,
        root,
        hooks,
        requests,
        facing,
        None,
        false,
        None,
    )
}

/// [`served_trusting`] with boot's tick schedule spawned over the door (`Served::spawn_ticks`,
/// as `main` runs it once the app is built), the deployment's `advanced.allow_destinations`
/// naming `allow`: the cells that read a delivery the door makes on its own.
fn served_pushing(
    instance: &'static str,
    section: &str,
    allow: Vec<String>,
    root: Vec<u8>,
) -> Served {
    served_core(
        instance,
        section,
        busbar_kernel::config::Destinations {
            block_private_addresses: true,
            allow,
            ..Default::default()
        },
        None,
        Some(root),
        None,
        None,
        Facing::Routes,
        None,
        true,
        None,
    )
}

/// [`served_pushing`] over the process's own connector shape (the public roots alone, no test
/// root), the plane's `agent_push.ca` written as `push_ca` when given: the cells that read which
/// receivers a delivery trusts.
fn served_push_trusting(
    instance: &'static str,
    section: &str,
    allow: Vec<String>,
    push_ca: Option<String>,
) -> Served {
    served_core(
        instance,
        section,
        busbar_kernel::config::Destinations {
            block_private_addresses: true,
            allow,
            ..Default::default()
        },
        None,
        None,
        None,
        None,
        Facing::Routes,
        None,
        true,
        push_ca,
    )
}

/// `der`, one certificate, as the PEM an operator writes.
fn pem_of(der: &[u8]) -> String {
    use base64::Engine as _;
    let text = base64::engine::general_purpose::STANDARD.encode(der);
    let lines: Vec<&str> = text
        .as_bytes()
        .chunks(64)
        .map(|c| std::str::from_utf8(c).expect("base64 is ASCII"))
        .collect();
    format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        lines.join("\n")
    )
}

/// What the deployment prices the agent door at, for the cells that read money: the card's rate
/// per payload byte of `planner` (none = no `agents.rate_card`, billing off), the plane's
/// per-request fee in minor units, and the caller's group `budget` cap in minor units.
struct Priced {
    bytes_rate: Option<u64>,
    fee: i64,
    budget: u64,
}

/// [`served`] over a deployment pricing the door as `priced`: the caller's group capped at its
/// budget, the card and the fee as `priced` states them.
fn served_priced(instance: &'static str, section: &str, priced: &Priced) -> Served {
    served_core(
        instance,
        section,
        busbar_kernel::config::Destinations {
            block_private_addresses: true,
            ..Default::default()
        },
        None,
        None,
        None,
        None,
        Facing::Routes,
        Some(priced),
        false,
        None,
    )
}

/// [`served_full`] over a deployment that prices the door when `priced` is given.
#[allow(clippy::too_many_arguments)]
fn served_core(
    instance: &'static str,
    section: &str,
    destinations: busbar_kernel::config::Destinations,
    allowed_pools: Option<Vec<String>>,
    root: Option<Vec<u8>>,
    hooks: Option<AgentHooks>,
    requests: Option<u64>,
    facing: Facing,
    priced: Option<&Priced>,
    ticking: bool,
    push_ca: Option<String>,
) -> Served {
    bootstrap::child();
    let directory = crate::root::test_plugins::scratch(&format!(
        "{instance}-{}",
        busbar_kernel::door::op_id().counter(),
    ));
    bootstrap::migrate(instance, &directory);
    served_core_on(
        instance,
        section,
        destinations,
        allowed_pools,
        root,
        hooks,
        requests,
        facing,
        priced,
        ticking,
        push_ca,
        &directory,
        false,
    )
}

#[allow(clippy::too_many_arguments)]
fn served_core_on(
    instance: &'static str,
    section: &str,
    destinations: busbar_kernel::config::Destinations,
    allowed_pools: Option<Vec<String>>,
    root: Option<Vec<u8>>,
    hooks: Option<AgentHooks>,
    requests: Option<u64>,
    facing: Facing,
    priced: Option<&Priced>,
    ticking: bool,
    push_ca: Option<String>,
    directory: &std::path::Path,
    initialize: bool,
) -> Served {
    let _ = tracing_subscriber::fmt()
        .with_test_writer()
        .with_max_level(tracing::Level::WARN)
        .try_init();
    let groups: BTreeMap<String, busbar_kernel::config::GroupCfg> = requests
        .map(|amount| (busbar_kernel::config::groups::LimitMetric::Requests, amount))
        .or_else(|| priced.map(|p| (busbar_kernel::config::groups::LimitMetric::Budget, p.budget)))
        .map(|(metric, amount)| {
            let limit = busbar_kernel::config::groups::LimitCfg {
                metric,
                amount,
                per: Some(busbar_kernel::config::groups::LimitWindow::Total),
                scope: None,
                on_exhaust: None,
                downgrade_to: None,
                admission: None,
                on_exhaustion: None,
            };
            let cfg = busbar_kernel::config::GroupCfg {
                parent: None,
                enabled: true,
                limits: vec![limit],
                ..Default::default()
            };
            (format!("{instance}-group"), cfg)
        })
        .into_iter()
        .collect();
    crate::dist_root_install::install();
    crate::root::connector::install_io_reactor();
    let live: Arc<std::sync::OnceLock<std::sync::Weak<busbar_kernel::state::AppHandle>>> =
        Arc::default();
    let observed_destinations = Arc::new(reported_observations::Destinations::new(
        crate::root::connector::guard_for(&destinations).expect("the production destination guard"),
    ));
    let judge: Arc<dyn busbar_kernel::host_services::DestJudge> = observed_destinations.clone();
    let rules = Arc::new(crate::root::door_steps::Rules::hearing(judge.clone()));

    // The Store and optional hook are freshly built external products. Their signed archives go
    // through normal registry admission; the retained archive digest also authorizes Store boot.
    // A signed dropped Store must have its own product identity, even when the surrounding
    // test binary uses its compiled-in memory Store for unrelated cases.
    let sqlite_image = std::env::var_os("BUSBAR_TEST_SQLITE_CDYLIB");
    let mut store_module = None;
    let mut hook_module = None;
    let mut fetch = Vec::new();
    for (kind, variable) in [
        ("store", "BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN"),
        ("hook", "BUSBAR_TEST_WEBREQUEST_CDYLIB"),
    ] {
        if kind == "hook" && hooks.is_none() {
            continue;
        }
        let path = std::path::PathBuf::from(
            if kind == "store" {
                sqlite_image.clone()
            } else {
                None
            }
            .or_else(|| std::env::var_os(variable))
            .expect(variable),
        );
        assert!(
            path.is_absolute() && path.is_file(),
            "{variable} is an actual image"
        );
        let statement = rendering_of_library(&path)
            .expect("the actual product statement reads")
            .expect("the actual product states itself");
        let name = busbar_contract::abi::mechanism::rendering::read(&statement)
            .expect("the actual product statement is valid")
            .name;
        let mut manifest = crate::root::test_plugins::manifest(kind, &name, "third-party");
        manifest.statement = Some(hex::encode(statement));
        if kind == "hook" {
            manifest.needs.prompt = busbar_contract::plugin_rows::NeedLevel::Rw;
            manifest.needs.user = busbar_contract::plugin_rows::NeedLevel::Ro;
            hook_module = Some(name);
        } else {
            store_module = Some(name);
        }
        let archive = crate::root::test_plugins::signed(
            &crate::root::test_plugins::key(0x33),
            manifest,
            &std::fs::read(path).expect("the actual image reads"),
        );
        let filename = format!("{kind}.tar.gz");
        fetch.push(busbar_kernel::config::PluginFetch::Url(
            busbar_kernel::config::UrlFetch {
                url: format!("https://fixtures.invalid/{filename}"),
                sha256: Some(crate::root::loader::sign::sha256_hex(&archive)),
            },
        ));
        std::fs::write(directory.join(filename), archive).expect("stage the signed actual product");
    }
    let module = store_module.expect("the fixture always stages the actual Store");
    let mut settings: serde_json::Value = serde_json::from_str(
        &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
    )
    .expect("the actual Store settings are JSON");
    // Independent deployments must not inherit another cell's durable virtual keys or groups.
    if sqlite_image.is_some() {
        settings = serde_json::json!({"db_path": directory.join("governance.sqlite")});
    } else if settings.get("db_path").is_some() {
        settings["db_path"] = serde_json::json!(directory.join("governance.sqlite"));
    }
    if initialize {
        bootstrap::create(directory, &settings);
    }
    let operator_file = directory.join("operator.token");
    std::fs::write(&operator_file, ADMIN_TOKEN).expect("the normal operator credential");
    let signing_file = directory.join("signing.key");
    std::fs::write(&signing_file, hex::encode([9u8; 32])).expect("the normal signing credential");
    let mut sections: BTreeMap<&'static str, serde_yaml::Value> = BTreeMap::new();
    if facing != Facing::Unconfigured {
        sections.insert(
            surface("section"),
            serde_yaml::from_str(section).expect("a section"),
        );
    }
    if let Some(priced) = priced {
        let section = sections
            .get_mut(surface("section"))
            .expect("a priced agent section");
        // Keep a numeric YAML scalar; JSON arbitrary-precision numbers serialize as a map.
        section["fees"] = serde_yaml::to_value(BTreeMap::from([("per_request", priced.fee)]))
            .expect("the agent section's configured fee");
        if let Some(rate) = priced.bytes_rate {
            section["rate_card"] = serde_yaml::from_str(&format!(
                "{}:planner: {{ units: {{ {}: {rate} }} }}",
                surface("resource_kind"),
                surface("bytes_class"),
            ))
            .expect("the agent section's configured rate");
        }
    }
    if let Some(ca) = push_ca {
        sections.insert(
            root_facts::PUSH_SECTION,
            serde_yaml::to_value(serde_json::json!({(root_facts::PUSH_CA_KEY): ca}))
                .expect("the owned push trust section"),
        );
    }
    let mut hook_peers = Vec::new();
    let mut hook_defs = serde_json::Map::new();
    if let Some(hooks) = hooks {
        let mut names = Vec::new();
        for (name, mut def) in hooks.defs {
            names.push(name.clone());
            let settings = def["settings"].clone();
            let listener =
                std::net::TcpListener::bind("127.0.0.1:0").expect("the hook policy peer binds");
            listener
                .set_nonblocking(true)
                .expect("the hook listener is nonblocking");
            let endpoint = format!(
                "http://{}/hook",
                listener.local_addr().expect("the hook address")
            );
            let listener = tokio::net::TcpListener::from_std(listener).expect("the hook listener");
            let router = axum::Router::new().route("/hook", axum::routing::post(
                move |axum::Json(body): axum::Json<serde_json::Value>| {
                    let settings = settings.clone();
                    async move {
                        let reject = settings["reject_if_contains"].as_str().is_some_and(|needle| {
                            body["request"]["messages"].to_string().contains(needle)
                        });
                        axum::Json(if reject {
                            serde_json::json!({"reject": {"status": 403, "message": "blocked by test gate"}})
                        } else if body["op"] == "transform" {
                            settings.get("raw_transform_reply").cloned()
                                .unwrap_or_else(|| serde_json::json!({}))
                        } else {
                            settings.get("raw_decide_reply").cloned()
                                .unwrap_or_else(|| serde_json::json!({}))
                        })
                    }
                }
            ));
            hook_peers.push(tokio::spawn(async move {
                axum::serve(listener, router)
                    .await
                    .expect("the hook policy peer serves");
            }));
            def["module"] = hook_module
                .as_ref()
                .expect("the actual hook is staged")
                .clone()
                .into();
            def["settings"] = serde_json::json!({"url": endpoint});
            hook_defs.insert(name, def);
        }
        sections
            .get_mut(surface("section"))
            .expect("a hooked agent section")[hooks.agent]["hooks"] =
            serde_yaml::to_value(names).expect("the agent's hook names");
    }
    let mut deployment = serde_json::json!({
        "providers": {}, "models": {}, "public_url": "https://gw.example",
        "per_request_fee": if priced.is_some() { 0 } else { 1 },
        "identity-providers": {
            (busbar_kernel::config::operator_provider()): {
                "module": busbar_kernel::config::operator_provider(),
                "token": {"file": operator_file}
            }
        },
        "auth": {
            "chain": ["keys"], "admin_auth": [busbar_kernel::config::operator_provider()],
            "signing_key": {"file": signing_file}
        },
        "advanced": {
            "block_private_addresses": destinations.block_private_addresses,
            "allow_destinations": destinations.allow,
        },
        "security": {
            "blocked_metadata_hosts": destinations.blocked,
            "allow_metadata_hosts": destinations.legacy_allow,
            "allow_all_metadata": destinations.allow_all_metadata,
        },
        "store": {"module": module, "settings": settings},
        "hooks": hook_defs,
    });
    for (key, value) in &sections {
        deployment[*key] = serde_json::to_value(value).expect("the deployment section");
    }
    let deploy = busbar_kernel::config::deploy_from_deserializer(deployment.clone())
        .expect("the deployment parses through the normal grammar");
    let mut config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the deployment resolves through the normal root");
    config.groups = groups.clone();
    // Feed the door the same normal deployment projection as production: ledger-owned fees
    // and rate cards are lifted, while the declared failover pools retain their operator grammar.
    if let Some(section) = deploy.door_sections().remove(surface("section")) {
        sections.insert(surface("section"), section);
    }
    sections = crate::root::serve::with_pools(
        sections,
        &crate::root::serve::door_pools(&config.plane_pools),
    );
    let mut plugins = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
        fetch,
        ..Default::default()
    };
    plugins
        .trust
        .publishers
        .push(busbar_kernel::config::PluginPublisher {
            name: "third-party".into(),
            public_key: hex::encode(
                crate::root::test_plugins::key(0x33)
                    .verifying_key()
                    .as_bytes(),
            ),
        });
    for step in crate::ROOT_UNITS.iter().filter_map(|unit| unit.on_config) {
        step(&config.limits);
    }
    let opened = futures::executor::block_on(busbar_kernel::appbuild::bootstrap_config_store(
        &config, &plugins,
    ))
    .expect("normal bootstrap admits and opens the signed actual Store");
    let expected_store_fingerprint = busbar_kernel::host_record_bootstrap::store_fingerprint(
        &serde_json::to_value(&config.store).expect("actual effective Store selection"),
    );
    let refuse = Arc::new(std::sync::Mutex::new(None));
    let core =
        futures::executor::block_on(crate::root::real_store::core_over(Arc::new(Refusing {
            inner: opened,
            named: refuse.clone(),
        })));
    let bootstrap_receipt = initialize
        .then(|| bootstrap::initialize(instance, directory, &config, &plugins, &core, &deployment));
    let rules: Arc<dyn busbar_kernel::appbuild::RootRules> = rules;
    let (app, rotate, limits) =
        futures::executor::block_on(busbar_kernel::appbuild::build_app_from_config_with_store(
            config,
            plugins.clone(),
            None,
            Default::default(),
            Default::default(),
            (None, None),
            None,
            &rules,
            Some(core),
            true,
        ))
        .expect("the production builder boots the actual Store-backed application");
    limits.stage_boot();
    let app = Arc::new(app);
    // A cold fixture and its serving reopen share this process. Drain the prior
    // native audit originals before assigning this attachment's test owner.
    futures::executor::block_on(busbar_kernel::audit::auditlog::register_test_audit_stream(
        &app,
    ));
    futures::executor::block_on(busbar_kernel::boot::hydrate_all(&app))
        .expect("normal startup hydrates the actual durable admin audit stream");
    let book = futures::executor::block_on(crate::root::boot::book(&app, &module))
        .expect("the normal durable node book opens");
    futures::executor::block_on(limits.keep()).expect("the boot card activates");
    if let Some(rotate) = rotate {
        futures::executor::block_on(rotate);
    }
    let ctx = crate::root::linked::BookCtx {
        book: &book,
        app: &app,
    };
    for step in crate::ROOT_UNITS.iter().filter_map(|unit| unit.on_book) {
        step(&ctx);
    }
    let gov = app
        .governance
        .as_ref()
        .expect("normal Store-backed governance")
        .clone();
    let (key, token) = futures::executor::block_on(gov.mint_signed_async(
        NewKeySpec {
            name: "delegator".into(),
            allowed_pools,
            group: groups.keys().next().cloned(),
            ..Default::default()
        },
        4_000_000_000,
        busbar_kernel::store::now(),
    ))
    .expect("mint the normal signed caller token");
    futures::executor::block_on(gov.hydrate_budgets_async(&app.cost, 0)).expect("hydrate");

    let services = crate::root::serve::LateServices::new();
    let kernel = Arc::new(crate::root::serve::kernel_services(judge.clone()));
    services
        .install_kernel(kernel.clone(), kernel.clone())
        .expect("install the actual KernelServices");
    crate::root::serve::attach(
        &services,
        Some(&gov),
        Some(gov.clone()),
        &app.demotion_record,
        &[],
    );
    if let Some(receipt) = bootstrap_receipt {
        futures::executor::block_on(kernel.arm_record_bootstrap(
            receipt,
            &expected_store_fingerprint,
            |schema, key, _| {
                busbar_kernel::persistence::scoped::migration_address(false, instance, schema, key)
                    .map_err(|_| "invalid fixture witness owner")
            },
        ))
        .expect("the actual host consumes the committed fresh-store witness");
    }
    let dispatcher = Arc::new(crate::root::dispatch::build(1, &services));
    crate::root::connector::install_io(&dispatcher);
    let settings = busbar_contract::transport::TransportSettings::default();
    let transports = crate::root::connector::entries(crate::LINKED_TRANSPORT_DOORS, &settings)
        .expect("the actual distribution's external transport rows open");
    let connector = if let Some(root) = root {
        let tls = busbar_core_connector::tls::client::build_client_config(
            &busbar_contract::transport::trust::EgressTrust {
                extra_anchors: vec![root],
                ..Default::default()
            },
        )
        .expect("the actual connector trusts the peer's test CA");
        Arc::new(busbar_core_connector::Connector::serving(
            busbar_core_connector::registry::Transports::new(transports)
                .expect("the actual transport view"),
            busbar_core_connector::process::judge(judge, &[]),
            Some(Arc::new(tls)),
            dispatcher.conn_waker(),
        ))
    } else {
        busbar_core_connector::process::build_with_secrets(
            || Ok(transports),
            judge,
            &[],
            dispatcher.conn_waker(),
            crate::root::connector::pool_posture(&settings),
            busbar_kernel::config::secret::resolve_linked_string_at_config,
        )
        .expect("the actual production connector builds")
    };
    let row = LinkedRow::of(door()).expect("the actual linked A2A Statement");
    let plane = Arc::new(
        load_linked::<Plane>(
            &row,
            Bind {
                instance: Arc::from(instance),
                max_inflight_cap: 64,
                sink: Arc::new(FixtureDiagnostics),
                dispatcher: dispatcher.adopter(),
                conns: ConnTable::Host(connector.clone()),
            },
        )
        .expect("the actual linked A2A product binds"),
    );
    let node = Arc::new(Node::new());
    node.bind_book(book.durability.clone());
    let post = Arc::new(NodeEndPost::new(node));
    let money = Arc::new(PlaneMoney::new(
        gov.clone(),
        post.clone() as Arc<dyn EndPost>,
    ));
    let riding = Arc::new(Riding {
        inner: connector.clone(),
        opened: std::sync::Mutex::default(),
    });
    let providers = BTreeMap::new();
    let reach = crate::root::door_steps::DoorReach {
        providers: &providers,
        secrets: Arc::new(busbar_kernel::config::secret::SecretResolver::builtins_only()),
        auths: Arc::new(crate::root::door_steps::OutboundAuths::new(
            dispatcher.clone(),
            crate::LINKED.auths,
            None,
            ConnTable::Host(connector.clone()),
            busbar_kernel::diagnostics::Catalogue::NEUTRAL,
        )),
        conns: riding.clone(),
        stream_ceiling_secs: 600,
        catalog: None,
        models: None,
        upgrades: Vec::new(),
    };
    let hooks = crate::root::serve::HookStage {
        host: Arc::new({
            let live = live.clone();
            move || {
                busbar_kernel::plane_driver::engine_host(
                    &live
                        .get()
                        .expect("the serving handle is built")
                        .upgrade()
                        .expect("the serving handle outlives its request")
                        .load(),
                )
            }
        }),
        gov: gov.clone(),
        journal: None,
    };
    let mut composed = futures::executor::block_on(crate::root::serve::compose_planes(
        &[(instance.to_string(), plane)],
        &dispatcher,
        &services,
        &sections,
        Some("https://gw.example"),
        &|| money.clone(),
        Some(&crate::root::serve::DoorEgress {
            reach: &reach,
            journal: post.clone(),
        }),
        Some(&hooks),
        &app.serve_tables,
    ))
    .expect("the actual root composes the agent door");
    composed.post = Some(post.clone());
    composed.framers = Some(crate::root::serve::StreamFramers(Arc::new(move |claim| {
        connector.framer_for(claim)
    })));
    if ticking {
        composed.spawn_ticks();
    }
    let appliers = composed.appliers();
    let doors = crate::root::serve::door_routes(composed, || CARD.pin(), &[], &[])
        .expect("the actual root mounts the declared claims");
    let routes = doors.iter().map(|r| r.path.clone()).collect();
    let (router, admin, handle) =
        busbar_kernel::build_split_routers_serving(app.clone(), doors, 1 << 20, 0, false);
    assert!(
        live.set(Arc::downgrade(&handle)).is_ok(),
        "the serving handle is installed before any request runs"
    );
    services
        .kernel()
        .expect("the actual host is installed")
        .attach_standing(busbar_kernel::plane_driver::live_standing(handle.clone()));
    let router = router.layer(axum::Extension(ListenerScheme(
        busbar_contract::abi::host::service::SCHEME_PLAIN,
    )));
    let admin = crate::root::units_admin::mount_node(
        admin,
        1 << 20,
        &handle,
        gov.core_store_handle()
            .expect("admitted native admin persistence"),
        &book,
        None,
        &services,
        crate::root::adapters::BreakerPolicy::new(),
    )
    .expect("the normal native admin routes mount");
    let applied_planes = appliers.clone();
    handle.on_apply_async(Box::new(move |app| {
        let applied_planes = applied_planes.clone();
        Box::pin(async move { applied_planes.apply(&app).await })
    }));
    Served {
        kernel,
        router,
        admin,
        gov,
        app,
        key,
        token: caller_resource_token(token.expose(&busbar_kernel::seal::lend())),
        handle,
        book: book.durability.clone(),
        post,
        routes,
        refuse,
        riding,
        observed_destinations,
        deployment,
        plugins,
        rules,
        appliers,
        hook_peers,
    }
}

/// A JSON-RPC `method` POSTed to the agent `agent`'s claim (`""` = the plane's own unaddressed
/// endpoint, `/a2a`), bearing `token` or none.
fn rpc(
    agent: &str,
    method: &str,
    params: &str,
    token: Option<&str>,
) -> axum::http::Request<axum::body::Body> {
    let path = if agent.is_empty() {
        mount().to_string()
    } else {
        format!("{}/agents/{agent}", mount())
    };
    let mut req = axum::http::Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json");
    if let Some(token) = token {
        req = req.header("authorization", format!("Bearer {token}"));
    }
    req.body(axum::body::Body::from(format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"{method}","params":{params}}}"#
    )))
    .expect("a request")
}

/// The response's status and body text.
async fn answered(
    router: &axum::Router,
    req: axum::http::Request<axum::body::Body>,
) -> (StatusCode, String) {
    use tower::ServiceExt as _;
    let response = router
        .clone()
        .oneshot(req)
        .await
        .expect("the router answers");
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 1 << 16)
        .await
        .expect("the body");
    (status, String::from_utf8_lossy(&body).into_owned())
}

/// The root cell `governance-budget × a2a-server`: a keyed caller's unit addressed to one
/// approved agent is SERVED through the door and the governance ledger holds its one admitted
/// request on the presenting key.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_agent_unit_served_through_its_door_charges_the_presenting_key() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door";
    let agent = Agent::start(200, ANSWER).await;
    let s = served(instance, &agent.entry("planner", "1h"), false, None);
    approve(&s, "planner").await;
    let (status, _) = answered(&s.router, rpc("planner", "tasks/list", "{}", None)).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "an unkeyed caller is refused at the door's claim"
    );
    let (status, body) = answered(
        &s.router,
        rpc("planner", "tasks/list", "{}", Some(&s.token)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "served through the door: {body}");
    let usage = futures::executor::block_on(s.gov.usage_for_async(
        &s.app.cost,
        &s.key.id,
        busbar_kernel::store::now(),
    ))
    .expect("a read")
    .expect("the key exists");
    assert_eq!(
        usage.requests, 1,
        "one admitted request, on the presenting key"
    );
}

/// The far agent's healthy answer: one JSON-RPC message result.
const ANSWER: &str = r#"{"jsonrpc":"2.0","id":1,"result":{"kind":"message","messageId":"m-far","role":"agent","parts":[{"kind":"text","text":"done"}]}}"#;

/// A far agent on loopback answering every request with one JSON-RPC message result; each
/// request it was sent comes back on the channel, whole.
async fn far_agent() -> (u16, tokio::sync::mpsc::UnboundedReceiver<String>) {
    far_end(200, ANSWER).await
}

/// A far end on loopback answering every request `status` with `answer`; each request it was
/// sent comes back on the channel, whole.
async fn far_end(
    status: u16,
    answer: &'static str,
) -> (u16, tokio::sync::mpsc::UnboundedReceiver<String>) {
    far_end_answering(Arc::new(move |_| {
        Some(FarReply::of(status, answer.to_string()))
    }))
    .await
}

/// What a far end answers one request: its status, its extra head fields, its body, and how
/// long it takes to answer.
struct FarReply {
    status: u16,
    fields: Vec<(&'static str, String)>,
    body: String,
    delay_ms: u64,
}

impl FarReply {
    fn of(status: u16, body: String) -> Self {
        Self {
            status,
            fields: Vec::new(),
            body,
            delay_ms: 0,
        }
    }
}

/// What a far end answers one request (the request whole), or `None` to close the connection
/// unanswered (an agent that is down).
type Answering = Arc<dyn Fn(&str) -> Option<FarReply> + Send + Sync>;

/// The path an agent serves its card at, on its origin.
const CARD_PATH: &str = "GET /.well-known/agent-card.json ";

/// A far end on loopback answering each request as `answering` says; each request it was sent,
/// but a `GET` (a fetch of its card), comes back on the channel, whole.
async fn far_end_answering(
    answering: Answering,
) -> (u16, tokio::sync::mpsc::UnboundedReceiver<String>) {
    far_end_over(answering, None).await
}

/// One accepted far-end connection, in the clear or under TLS.
trait FarSocket: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> FarSocket for T {}

/// [`far_end_answering`], each connection secured by `tls` when given (a handshake that fails
/// is dropped unanswered).
async fn far_end_over(
    answering: Answering,
    tls: Option<tokio_rustls::TlsAcceptor>,
) -> (u16, tokio::sync::mpsc::UnboundedReceiver<String>) {
    far_end_observed(answering, tls, None).await
}

/// Counts accepted sockets before TLS or HTTP parsing, including malformed traffic.
async fn far_end_observed(
    answering: Answering,
    tls: Option<tokio_rustls::TlsAcceptor>,
    accepted: Option<Arc<std::sync::atomic::AtomicUsize>>,
) -> (u16, tokio::sync::mpsc::UnboundedReceiver<String>) {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a loopback port");
    let port = listener.local_addr().expect("its address").port();
    let (sent, heard) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((plain, _)) = listener.accept().await {
            if let Some(accepted) = &accepted {
                accepted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            let sent = sent.clone();
            let answering = Arc::clone(&answering);
            let tls = tls.clone();
            tokio::spawn(async move {
                let mut socket: Box<dyn FarSocket> = match tls {
                    None => Box::new(plain),
                    Some(tls) => match tls.accept(plain).await {
                        Ok(secured) => Box::new(secured),
                        Err(_) => return,
                    },
                };
                let mut buf = vec![0u8; 16 * 1024];
                let mut got = Vec::new();
                loop {
                    let Ok(n) = socket.read(&mut buf).await else {
                        return;
                    };
                    if n == 0 {
                        return;
                    }
                    got.extend_from_slice(&buf[..n]);
                    let text = String::from_utf8_lossy(&got).to_string();
                    if let Some(at) = text.find("\r\n\r\n") {
                        let length = text[..at]
                            .lines()
                            .find_map(|l| {
                                let (name, value) = l.split_once(':')?;
                                name.eq_ignore_ascii_case("content-length")
                                    .then(|| value.trim().parse::<usize>().ok())
                                    .flatten()
                            })
                            .unwrap_or(0);
                        if got.len() >= at + 4 + length {
                            break;
                        }
                    }
                }
                let text = String::from_utf8_lossy(&got).to_string();
                let answered = answering(&text);
                if !text.starts_with("GET ") {
                    let _ = sent.send(text);
                }
                let Some(FarReply {
                    status,
                    fields,
                    body: answer,
                    delay_ms,
                }) = answered
                else {
                    return;
                };
                if delay_ms > 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                }
                let extra: String = fields
                    .iter()
                    .map(|(name, value)| format!("{name}: {value}\r\n"))
                    .collect();

                let typed = fields
                    .iter()
                    .any(|(name, _)| name.eq_ignore_ascii_case("content-type"));
                let json = if typed {
                    ""
                } else {
                    "content-type: application/json\r\n"
                };
                let length = if fields
                    .iter()
                    .any(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                {
                    String::new()
                } else {
                    format!("content-length: {}\r\n", answer.len())
                };
                let reply = format!(
                    "HTTP/1.1 {status} X\r\n{json}{extra}{length}\
                     connection: close\r\n\r\n{answer}"
                );
                let _ = socket.write_all(reply.as_bytes()).await;
                let _ = socket.shutdown().await;
            });
        }
    });
    (port, heard)
}

/// The agents section registering `planner` (and, given, `scout`) at loopback `port`.
fn agents(port: u16, scout: bool) -> String {
    let mut section = format!(
        "planner: {{url: 'http://127.0.0.1:{port}/planner', pin: {{mechanism: unpinned}}}}"
    );
    if scout {
        section.push_str(&format!(
            "\nscout: {{url: 'http://127.0.0.1:{port}/scout', pin: {{mechanism: unpinned}}}}"
        ));
    }
    section
}

/// The presenting key's admitted requests on the governance ledger.
fn admitted(s: &Served) -> u64 {
    futures::executor::block_on(s.gov.usage_for_async(
        &s.app.cost,
        &s.key.id,
        busbar_kernel::store::now(),
    ))
    .expect("a read")
    .expect("the key exists")
    .requests
}

/// The `message/send` the relayed cells send.
const SEND: &str = r#"{"message":{"kind":"message","messageId":"m-1","role":"user","parts":[{"kind":"text","text":"plan"}]}}"#;

/// The root cell `net-guard × a2a-client`: an agent is reached over its member route (its own
/// `url`) only where the deployment's destination guard admits its address.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_agent_unit_dials_only_the_address_the_guard_admits() {
    let _one = PUBLISHING.lock().await;
    let mut agent = Agent::start(200, ANSWER).await;
    let section = agent.entry("planner", "1h");

    let blocked = "serve-agent-door-guarded";
    let s = served(blocked, &section, true, None);
    let (status, preview) = admin(&s, "/agents/planner/connect", "").await;
    assert_eq!(status, StatusCode::OK, "{preview}");
    assert_eq!(
        preview["state"], "error",
        "the guard refused the card fetch: {preview}"
    );
    assert_eq!(agent.fetches(), 0, "the agent never heard the card fetch");
    let (status, body) = answered(
        &s.router,
        rpc("planner", "message/send", SEND, Some(&s.token)),
    )
    .await;
    assert_ne!(
        status,
        StatusCode::OK,
        "a refused address is never served: {body}"
    );
    assert!(!agent.relayed(), "the far agent was never dialled");

    let open = "serve-agent-door-open";
    let s = served(open, &section, false, None);
    approve(&s, "planner").await;
    let (status, body) = answered(
        &s.router,
        rpc("planner", "message/send", SEND, Some(&s.token)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "relayed through the door: {body}");
    assert!(
        body.contains("m-far"),
        "the far agent's answer, relayed: {body}"
    );
    let head = agent.heard.recv().await.expect("the far agent was dialled");
    assert!(head.starts_with("POST /planner "), "{head}");
}

/// The root cell `governance-budget × a2a-client`: a relayed unit addressed to one agent is
/// served at that agent and its one admitted request is attributed to the presenting key.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_relayed_agent_unit_charges_the_presenting_key() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-charged";
    let mut agent = Agent::start(200, ANSWER).await;
    let s = served(instance, &agent.entry("planner", "1h"), false, None);
    approve(&s, "planner").await;
    let (status, body) = answered(
        &s.router,
        rpc("planner", "message/send", SEND, Some(&s.token)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "relayed through the door: {body}");
    agent.heard.recv().await.expect("the far agent was dialled");
    assert_eq!(
        admitted(&s),
        1,
        "one admitted request, on the presenting key"
    );
}

/// The sealed audit rows of this node's actual durable book, oldest first.
fn chain(s: &Served) -> Vec<busbar_kernel_audit::AuditRecord> {
    s.book.lock().expect("unpoisoned").audit_records.clone()
}

/// The root cells `audit-chain × a2a`, and the teller steps AUDIT, METER and EXIT over the
/// agent door: one relayed unit lands exactly ONE audit row on the kernel's chain.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_relayed_agent_unit_is_audited_on_the_chain_and_posts_one_line_once() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-audited";
    let mut agent = Agent::start(200, ANSWER).await;
    let s = served(instance, &agent.entry("auditor", "1h"), false, None);
    approve(&s, "auditor").await;
    let destination = crate::root::door_steps::plane_lane(surface("plane_key"), "auditor");
    let before = chain(&s).last().map_or(0, |e| e.seq);
    let (status, body) = answered(
        &s.router,
        rpc("auditor", "message/send", SEND, Some(&s.token)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "relayed through the door: {body}");
    agent.heard.recv().await.expect("the far agent was dialled");
    let all = chain(&s);
    let rows: Vec<_> = all
        .iter()
        .filter(|e| e.seq > before && e.what.destination.as_deref() == Some(destination.as_str()))
        .collect();
    assert_eq!(
        rows.len(),
        1,
        "exactly one audit row for the unit: {rows:?}; actual durable chain: {all:?}"
    );
    let row = rows[0];
    assert_eq!(row.what.op_class.as_str(), "message_send", "{row:?}");
    assert_eq!(
        row.outcome.unit_end,
        busbar_contract::caps::Outcome::Completed,
        "a served unit completes: {row:?}"
    );
    assert_eq!(
        row.outcome.finish,
        busbar_kernel_audit::FinishClass::Complete,
        "the complete answer was delivered: {row:?}"
    );
    assert!(!row.hash.is_empty(), "the row is sealed: {row:?}");
    let prev = all
        .iter()
        .find(|entry| entry.seq + 1 == row.seq)
        .expect("the connect/approve audit precedes the relayed unit");
    assert_eq!(
        row.prev_hash, prev.hash,
        "the row is chained to the one before it"
    );
    let ours = caller_counts(&s);
    assert_eq!(ours.len(), 1, "one record for the unit: {ours:?}");
    assert_eq!(s.post.open_units(), 0, "the unit's facts closed at its end");
    assert_eq!(admitted(&s), 1, "one admitted request");
}

/// The teller step ADMIT over the agent door: a caller whose group admits one request is
/// relayed once, and its second unit is refused `429` at admission, before the agent is dialled,
/// charging nothing more.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_agent_unit_past_its_callers_request_limit_is_refused_before_it_dials() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-limited";
    let mut agent = Agent::start(200, ANSWER).await;
    let s = served_limited(instance, &agent.entry("rationed", "1h"), 1);
    approve(&s, "rationed").await;
    let (status, body) = answered(
        &s.router,
        rpc("rationed", "message/send", SEND, Some(&s.token)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the first unit is admitted: {body}");
    assert!(agent.relayed(), "the first unit dialled");
    let (status, body) = answered(
        &s.router,
        rpc("rationed", "message/send", SEND, Some(&s.token)),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "the second unit is refused at admission: {body}"
    );
    let doc: serde_json::Value = serde_json::from_str(&body).expect("the plane's envelope");
    assert!(doc["error"]["code"].is_i64(), "{body}");
    assert!(!agent.relayed(), "the refused unit never dialled");
    assert_eq!(admitted(&s), 1, "the refusal charged nothing");
}

/// The teller step DECODE over the agent door: a body that is not JSON is refused with the
/// parse error's own `-32700` at the door's arrival, and nothing is relayed or charged.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_agent_unit_whose_body_is_not_json_is_refused_at_its_arrival() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-undecoded";
    let mut agent = Agent::start(200, ANSWER).await;
    let s = served(instance, &agent.entry("parser", "1h"), false, None);
    approve(&s, "parser").await;
    let req = axum::http::Request::builder()
        .method("POST")
        .uri(format!("{}/agents/parser", mount()))
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", s.token))
        .body(axum::body::Body::from("{ this is not json"))
        .expect("a request");
    let (status, body) = answered(&s.router, req).await;
    assert!(status.is_client_error(), "{status} {body}");
    let doc: serde_json::Value = serde_json::from_str(&body).expect("the plane's envelope");
    assert_eq!(doc["error"]["code"], -32700, "{body}");
    assert!(!agent.relayed(), "nothing was relayed");
    assert_eq!(admitted(&s), 0, "nothing was charged");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_rest_bodies_never_dispatch_or_charge_and_empty_cancel_still_dispatches() {
    let _one = PUBLISHING.lock().await;
    let mut agent = Agent::start_answering(
        200,
        Arc::new(|request| {
            let body = request.split_once("\r\n\r\n").unwrap().1;
            let envelope: serde_json::Value = serde_json::from_str(body).unwrap();
            serde_json::json!({"jsonrpc":"2.0", "id":envelope["id"], "result":{
                "kind":"task", "id":"backend-live", "contextId":"ctx", "status":{"state":"working"}
            }})
            .to_string()
        }),
    )
    .await;
    let s = served(
        "serve-agent-door-rest-malformed",
        &agent.entry("parser", "1h"),
        false,
        None,
    );
    approve(&s, "parser").await;
    let (status, body) = answered(
        &s.router,
        rpc("parser", "message/send", SEND, Some(&s.token)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let document: serde_json::Value = serde_json::from_str(&body).unwrap();
    let task = document["result"]["id"].as_str().unwrap();
    agent
        .heard
        .recv()
        .await
        .expect("the initial task was dispatched");
    let before_requests = admitted(&s);
    let billed_before = Billed::of(&s);
    let audit_rows = || {
        let caller = busbar_kernel_audit::Subject::PrincipalId(s.key.id.clone());
        s.book
            .lock()
            .expect("unpoisoned")
            .audit_records
            .iter()
            .filter(|record| record.subject == caller)
            .map(|record| ((record.node, record.seq), record.clone()))
            .collect::<BTreeMap<_, _>>()
    };
    let before_rows = audit_rows();
    let mut refused = 0;
    for target in [
        format!("{}/tasks/{task}:cancel", mount()),
        format!("{}/message:send", mount()),
        format!("{}/message:stream", mount()),
    ] {
        for body in ["{broken", "[]", "null", "false"] {
            let request = axum::http::Request::builder()
                .method("POST")
                .uri(&target)
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", s.token))
                .body(axum::body::Body::from(body))
                .unwrap();
            let (status, answer) = answered(&s.router, request).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{target}: {answer}");
            let document: serde_json::Value = serde_json::from_str(&answer).unwrap();
            assert_eq!(document["error"]["status"], "INVALID_ARGUMENT");
            assert!(
                !agent.relayed(),
                "a refused body must never reach the agent"
            );
            assert_eq!(admitted(&s), before_requests);
            refused += 1;
            let after_rows = audit_rows();
            assert_eq!(after_rows.len(), before_rows.len() + refused);
            for (identity, row) in &before_rows {
                assert_eq!(
                    after_rows.get(identity),
                    Some(row),
                    "a sealed row is unchanged"
                );
            }
            for (identity, row) in &after_rows {
                if before_rows.contains_key(identity) {
                    continue;
                }
                assert!(row.usage.lines.iter().all(|line| line.quantity == 0));
                assert_eq!(row.usage.fee_count, 0);
            }
            let billed_after = Billed::of(&s);
            assert_eq!(
                (
                    billed_after.requests,
                    billed_after.fees,
                    billed_after.bytes,
                    billed_after.spend
                ),
                (
                    billed_before.requests,
                    billed_before.fees,
                    billed_before.bytes,
                    billed_before.spend
                ),
                "a refused body changes no ledger amount"
            );
        }
    }
    let target = format!("{}/tasks/{task}:cancel", mount());
    let request = axum::http::Request::builder()
        .method("POST")
        .uri(&target)
        .header("content-type", "text/plain")
        .header("authorization", format!("Bearer {}", s.token))
        .body(axum::body::Body::from("{broken"))
        .unwrap();
    let (status, answer) = answered(&s.router, request).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{answer}");
    let document: serde_json::Value = serde_json::from_str(&answer).unwrap();
    assert_eq!(document["error"]["status"], "INVALID_ARGUMENT");
    assert!(
        answer.contains("request declared `text/plain`"),
        "head refusal precedes malformed-body decoding: {answer}"
    );
    assert!(!agent.relayed());
    assert_eq!(admitted(&s), before_requests);
    let billed_after = Billed::of(&s);
    assert_eq!(
        (
            billed_after.requests,
            billed_after.fees,
            billed_after.bytes,
            billed_after.spend
        ),
        (
            billed_before.requests,
            billed_before.fees,
            billed_before.bytes,
            billed_before.spend
        ),
        "a refused media type changes no ledger amount"
    );
    let request = axum::http::Request::builder()
        .method("POST")
        .uri(&target)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", s.token))
        .body(axum::body::Body::empty())
        .unwrap();
    let (status, body) = answered(&s.router, request).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "empty cancel remains legitimate: {body}"
    );
    let sent = agent
        .heard
        .recv()
        .await
        .expect("the empty cancel was dispatched");
    assert!(sent.contains("CancelTask") && sent.contains("backend-live"));
    assert_eq!(admitted(&s), before_requests + 1);
    assert_eq!(caller_counts(&s).last().unwrap().fee_count, 1);
}

/// A NOTIFICATION over the agent door (a JSON-RPC message with no `id`): acknowledged `202`
/// with no body at all, and never relayed, as the served engine answered it
/// (`jsonrpc::accepted`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_agent_notification_is_acknowledged_202_with_no_body_and_dials_nothing() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-notified";
    let mut agent = Agent::start(200, ANSWER).await;
    let s = served(instance, &agent.entry("notified", "1h"), false, None);
    approve(&s, "notified").await;
    for target in [format!("{}/agents/notified", mount()), mount().to_string()] {
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(&target)
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", s.token))
            .body(axum::body::Body::from(format!(
                r#"{{"jsonrpc":"2.0","method":"message/send","params":{SEND}}}"#
            )))
            .expect("a request");
        let (status, body) = answered(&s.router, req).await;
        assert_eq!(status, StatusCode::ACCEPTED, "{target}: {body}");
        assert!(body.is_empty(), "a notification is never answered: {body}");
        assert!(!agent.relayed(), "nothing was relayed");
        assert_eq!(admitted(&s), 0, "a notification accrues no request");
    }
}

/// An unaddressed unit selects the one agent reached by the caller's grant.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unaddressed_agent_unit_is_routed_to_the_one_agent_the_grant_reaches() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-select-one";
    let mut agent = Agent::start(200, ANSWER).await;
    let s = served(instance, &agent.entry("planner", "1h"), false, None);
    approve(&s, "planner").await;
    let (status, body) = answered(&s.router, rpc("", "message/send", SEND, Some(&s.token))).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "routed by scope and relayed: {body}"
    );
    assert!(body.contains("m-far"), "the far agent's answer: {body}");
    let head = agent.heard.recv().await.expect("the one agent was dialled");
    assert!(head.starts_with("POST /planner "), "{head}");
}

/// SELECT, SEVERAL REACH: with two approved agents in the caller's grant, the unaddressed unit
/// is refused before any dial, in 1.5.5's words (`-32602`, 400), naming the agents it reaches so
/// it can address one; while neither is approved, none serves, and it is 1.5.5's none-refusal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unaddressed_agent_unit_several_agents_reach_is_refused_naming_them() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-select-several";
    let mut agent = Agent::start(200, ANSWER).await;
    let section = format!(
        "{}\n{}",
        agent.entry("planner", "1h"),
        agent.entry("scout", "1h")
    );
    let s = served(instance, &section, false, None);
    let (status, body) = answered(&s.router, rpc("", "message/send", SEND, Some(&s.token))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let doc: serde_json::Value = serde_json::from_str(&body).expect("a JSON-RPC envelope");
    assert_eq!(
        (
            doc["error"]["code"].clone(),
            doc["error"]["message"].clone()
        ),
        (
            (-32004).into(),
            "no agent this key may reach can serve this shape of task".into()
        ),
        "neither is approved, so none serves: {body}"
    );
    approve(&s, "planner").await;
    approve(&s, "scout").await;
    let (status, body) = answered(&s.router, rpc("", "message/send", SEND, Some(&s.token))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let doc: serde_json::Value = serde_json::from_str(&body).expect("a JSON-RPC envelope");
    assert_eq!(doc["error"]["code"], -32602, "{body}");
    assert_eq!(
        doc["error"]["message"],
        format!(
            "2 agents this key may reach can serve this shape of task, so this endpoint \
             cannot choose one for you. Address the agent directly at `{}/agents/{{id}}` — \
             the ids are: planner, scout",
            mount()
        )
        .as_str(),
        "{body}"
    );
    assert!(!agent.relayed(), "nothing was dialled");
    assert_eq!(admitted(&s), 0, "nothing charged");
}

/// SELECT, NONE REACHES: a caller whose grant names no agent gets, on the unaddressed endpoint,
/// 1.5.5's answer (`-32004`, 400), the same a caller with no grant gets for a named agent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unaddressed_agent_unit_no_agent_reaches_is_refused_in_its_1_5_5_words() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-select-none";
    let (port, mut heard) = far_agent().await;
    let s = served(instance, &agents(port, true), false, Some(Vec::new()));
    let (status, body) = answered(&s.router, rpc("", "message/send", SEND, Some(&s.token))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let doc: serde_json::Value = serde_json::from_str(&body).expect("a JSON-RPC envelope");
    assert_eq!(doc["error"]["code"], -32004, "{body}");
    assert_eq!(
        doc["error"]["message"], "no agent this key may reach can serve this shape of task",
        "{body}"
    );
    assert!(heard.try_recv().is_err(), "nothing was dialled");
    assert_eq!(admitted(&s), 0, "nothing charged");
}

/// THE GRANT'S REFUSAL, in predev's bytes (1.5.5's `InboundRefusal::NotInScope`: `403`,
/// `-32004`, no id), its sentence naming `this key` where predev named the key's id: a plane
/// never sees the raw principal (BUSBAR-1.6.0.md l.2639-2641).
fn assert_not_granted(status: StatusCode, body: &str, agent: &str) {
    assert_eq!(status, StatusCode::FORBIDDEN, "the grant's refusal: {body}");
    let doc: serde_json::Value = serde_json::from_str(body).expect("an envelope");
    assert_eq!(doc["error"]["code"], -32004, "{body}");
    assert_eq!(
        doc["error"]["message"],
        format!("this key is not granted `agent:{agent}`"),
        "{body}"
    );
    assert_eq!(doc["id"], serde_json::Value::Null, "{body}");
}

/// The root cell `catalogue × a2a-server`: a unit addressed to an agent outside the caller's
/// grant is refused before it dials, and charges nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_agent_unit_outside_the_callers_grant_is_refused_before_it_dials() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-ungranted";
    let (port, mut heard) = far_agent().await;
    let s = served(instance, &agents(port, false), false, Some(Vec::new()));
    for (method, params) in [
        ("message/send", SEND),
        ("ListTasks", "{}"),
        ("tasks/list", "{}"),
    ] {
        let (status, body) =
            answered(&s.router, rpc("planner", method, params, Some(&s.token))).await;
        assert_not_granted(status, &body, "planner");
        assert!(heard.try_recv().is_err(), "{method}: nothing was dialled");
        assert_eq!(admitted(&s), 0, "{method}: nothing charged");
    }
}

/// The caller's key must be LIVE for busbar to spend its hop on the caller's behalf (predev's
/// `creds::authorise_egress`, `KeyNotLive`): a key deleted after it was served is refused at
/// the door's next unit, and the agent is never dialled for it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_agent_unit_from_a_key_that_is_no_longer_live_never_dials() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-key-gone";
    let mut agent = Agent::start(200, ANSWER).await;
    let s = served(instance, &agent.entry("planner", "1h"), false, None);
    approve(&s, "planner").await;
    let (status, body) = answered(
        &s.router,
        rpc("planner", "message/send", SEND, Some(&s.token)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the live key is served: {body}");
    assert!(agent.relayed(), "the live key's unit dialled");
    let _ = futures::executor::block_on(s.gov.delete_key(&s.key.id));
    let (status, body) = answered(
        &s.router,
        rpc("planner", "message/send", SEND, Some(&s.token)),
    )
    .await;
    assert!(
        status.is_client_error(),
        "a key that is not live is refused: {status} {body}"
    );
    assert!(!agent.relayed(), "and the agent is never dialled for it");
}

/// The root cell `disposition × a2a-client`: a relayed unit to an approved agent that has gone
/// down (its verification still fresh, so the hop is sent) ends inside its unit — the caller
/// answered in the plane's own envelope, not left hanging.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_relayed_agent_unit_to_an_agent_that_is_down_ends_inside_its_unit() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-down";
    let agent = Agent::start(200, ANSWER).await;
    let s = served(instance, &agent.entry("planner", "1h"), false, None);
    approve(&s, "planner").await;
    let (status, body) = answered(
        &s.router,
        rpc("planner", "message/send", SEND, Some(&s.token)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "served while it is up: {body}");
    agent.go_down();
    let (status, body) = answered(
        &s.router,
        rpc("planner", "message/send", SEND, Some(&s.token)),
    )
    .await;
    assert!(
        status.is_server_error(),
        "a down agent is the far end's failure: {status} {body}"
    );
    let doc: serde_json::Value = serde_json::from_str(&body).expect("the plane's envelope");
    assert_eq!(doc["jsonrpc"], "2.0", "{body}");
    assert!(doc["error"]["code"].is_i64(), "{body}");
}

/// The root cells `breaker-trip` and `breaker-fastfail × a2a-client`: an approved agent that
/// keeps failing records into its member's breaker until it opens, and the next unit is refused
/// `breaker_open` before it dials.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failing_agent_trips_its_breaker_and_the_next_unit_is_refused_before_it_dials() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-breaker";
    let mut agent = Agent::start(503, r#"{"error":"down"}"#).await;
    let s = served(instance, &agent.entry("planner", "1h"), false, None);
    approve(&s, "planner").await;
    let mut dials = 0usize;
    let mut tripped = None;
    for call in 0..32 {
        let (_, body) = answered(
            &s.router,
            rpc("planner", "message/send", SEND, Some(&s.token)),
        )
        .await;
        while agent.heard.try_recv().is_ok() {
            dials += 1;
        }
        if body.contains("breaker_open") {
            tripped = Some((call, dials));
            break;
        }
    }
    let (_, dialled) = tripped.expect("the breaker opened within 32 failing calls");
    assert!(
        dialled > 0,
        "it tripped on failures the agent answered: {dialled}"
    );
    let (_, body) = answered(
        &s.router,
        rpc("planner", "message/send", SEND, Some(&s.token)),
    )
    .await;
    assert!(
        body.contains("breaker_open"),
        "a tripped agent fast-fails: {body}"
    );
    assert!(!agent.relayed(), "the fast-failed unit never dialled");
}

/// What one unit's audit record carries: what its plane reported, by class, and its fee count.
#[derive(Debug, Clone)]
struct Counted {
    classes: BTreeMap<String, u64>,
    fee_count: u32,
}

/// Every unit the caller ran, oldest first, as its one audit record carries it: the node keeps no
/// money line (busbar's money design, the section on what a node keeps); a unit's counts are the
/// governance ledger's, and its record names them.
fn caller_counts(s: &Served) -> Vec<Counted> {
    let caller = busbar_kernel_audit::Subject::PrincipalId(s.key.id.clone());
    s.book
        .lock()
        .expect("unpoisoned")
        .audit_records
        .iter()
        .filter(|r| r.subject == caller)
        .map(|r| Counted {
            classes: r
                .usage
                .lines
                .iter()
                .map(|l| {
                    (
                        l.class.as_str().to_string(),
                        l.quantity
                            .whole_u64()
                            .expect("A2A byte and fee fixture counts are exact whole units"),
                    )
                })
                .collect(),
            fee_count: r.usage.fee_count,
        })
        .collect()
}

/// The count a record carries under `class`, `0` when it carries none.
fn counted(counts: &Counted, class: &str) -> u64 {
    counts.classes.get(class).copied().unwrap_or(0)
}

/// The root cells `billed-bytes × a2a-client` and the agent fee unit: a served hop's one line
/// counts the request body it sent and the response body it read, both ways, under the plane's
/// bytes class, and the plane's per-request fee unit exactly once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_agent_hop_ledgers_the_bodies_it_moved_and_its_fee_unit_once() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-billed-bytes";
    let mut agent = Agent::start(200, ANSWER).await;
    let s = served(instance, &agent.entry("planner", "1h"), false, None);
    approve(&s, "planner").await;
    let (status, body) = answered(
        &s.router,
        rpc("planner", "message/send", SEND, Some(&s.token)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let heard = agent.heard.recv().await.expect("the far agent was dialled");
    let sent = heard.split_once("\r\n\r\n").map_or(0, |(_, b)| b.len());
    assert!(sent > 0, "the hop carried a body: {heard}");
    let lines = caller_counts(&s);
    assert_eq!(lines.len(), 1, "one line for the unit: {lines:?}");
    assert_eq!(
        counted(&lines[0], surface("bytes_class")),
        (sent + ANSWER.len()) as u64,
        "the request body sent and the response body read: {lines:?}"
    );

    assert_eq!(lines[0].fee_count, 1, "the fee unit, once: {lines:?}");
}

/// The root cells `billed-bytes` and the agent fee unit, refused before the socket: every hop
/// that LEFT for a failing agent counts the bodies it moved and keeps its fee.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_agent_hop_refused_before_the_socket_counts_no_bytes_and_keeps_no_fee() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-refused-unbilled";
    let failing = r#"{"error":"down"}"#;
    let mut agent = Agent::start(503, failing).await;
    let s = served(instance, &agent.entry("planner", "1h"), false, None);
    approve(&s, "planner").await;
    let mut tripped = false;
    for _ in 0..32 {
        let (_, body) = answered(
            &s.router,
            rpc("planner", "message/send", SEND, Some(&s.token)),
        )
        .await;
        if body.contains("breaker_open") {
            tripped = true;
            break;
        }
    }
    assert!(tripped, "the breaker opened within 32 failing calls");
    let left = caller_counts(&s);
    assert!(!left.is_empty(), "the hops that left were ledgered");
    let dialled: Vec<_> = left
        .iter()
        .filter(|c| counted(c, surface("bytes_class")) > 0)
        .collect();
    assert!(
        !dialled.is_empty(),
        "a hop that left counts its bodies: {left:?}"
    );
    for c in &dialled {
        assert!(
            counted(c, surface("bytes_class")) > failing.len() as u64,
            "its request and the agent's refusal: {c:?}"
        );
        assert_eq!(c.fee_count, 1, "a hop that left keeps its fee: {c:?}");
    }
    let before = left.len();
    while agent.heard.try_recv().is_ok() {}
    let (_, body) = answered(
        &s.router,
        rpc("planner", "message/send", SEND, Some(&s.token)),
    )
    .await;
    assert!(body.contains("breaker_open"), "fast-failed: {body}");
    let after = caller_counts(&s);
    assert_eq!(
        after.len(),
        before + 1,
        "the refused unit has its own audit record: {after:?}"
    );
    for c in after.iter().skip(before) {
        assert_eq!(
            counted(c, surface("bytes_class")),
            0,
            "a unit refused before the socket counts no bytes: {c:?}"
        );
        assert_eq!(c.fee_count, 0, "and keeps no fee: {c:?}");
    }
    assert!(!agent.relayed(), "the fast-failed unit never dialled");
}

/// The agent section's fees: `per_request` is the unit the plane counts, so it validates, and
/// `per_session` (a unit the plane never counts, so it would charge nothing) is refused naming
/// the counted list, by the kernel's one rule over the door's declared fee units.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_agent_sections_per_request_fee_validates_and_per_session_is_refused() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-fees";
    let agent = Agent::start(200, ANSWER).await;

    let _s = served(instance, &agent.entry("planner", "1h"), false, None);

    crate::dist_root_install::install();
    let with_fees = |per_request: i64, per_session: i64| {
        let deploy = busbar_kernel::config::deploy_from_yaml_str(
            "store: {module: memory}\nproviders: {}\nmodels: {}\n",
        )
        .expect("the fee validation deployment parses");
        let mut cfg = busbar_kernel::config::resolve(&deploy, &Default::default())
            .expect("the fee validation deployment resolves");
        cfg.plane_fees = [(
            surface("plane_key").to_string(),
            busbar_kernel_ledger::cost::PlaneFees {
                per_request,
                per_session,
            },
        )]
        .into_iter()
        .collect();
        busbar_kernel::config_validate::validate(&cfg)
            .err()
            .unwrap_or_default()
    };
    let refusal = format!(
        "{}.fees.{} is not counted by this plane (counted: {}); remove it",
        surface("section"),
        busbar_contract::plane::PER_SESSION,
        busbar_contract::plane::PER_REQUEST
    );
    assert!(
        with_fees(0, 40).contains(&refusal),
        "per_session is refused: {:?}",
        with_fees(0, 40)
    );
    assert!(
        !with_fees(2, 0).iter().any(|e| e.contains(".fees.")),
        "a counted fee validates: {:?}",
        with_fees(2, 0)
    );
}

/// THE STATUS FIRST (COORDINATOR ruling 2026-10-07 on finding A: predev `relay.rs:1813-1819`
/// turns any non-2xx into a failure from the status alone): an agent that answers `502` is failing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_agent_answering_protocol_errors_under_a_502_trips_its_breaker() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-breaker-protocol-error";
    let mut agent = Agent::start(
        502,
        r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32001,"message":"Task not found"}}"#,
    )
    .await;
    let s = served(instance, &agent.entry("planner", "1h"), false, None);
    approve(&s, "planner").await;
    let mut tripped = None;
    for call in 0..8 {
        let (_, body) = answered(
            &s.router,
            rpc("planner", "message/send", SEND, Some(&s.token)),
        )
        .await;
        if body.contains("breaker_open") {
            tripped = Some(call);
            assert!(
                !agent.relayed(),
                "call {call}: a tripped cell dials nothing"
            );
            break;
        }
        assert!(agent.relayed(), "call {call} was dialled: {body}");
    }
    let tripped = tripped.expect("a protocol error under a 502 opens the agent's cell");
    assert!(
        tripped >= 5,
        "the cell opens on the trip's five outcomes, never sooner: call {tripped}"
    );
}

/// THE TWIN: an error the protocol defines on a `2xx` is the destination ANSWERING, the work
/// failing and not the wire (predev `classify_hop` `:1575`: `BackendError` is a success to the
/// breaker).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_agent_answering_protocol_errors_under_a_200_never_trips_its_breaker() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-breaker-protocol-error-2xx";
    let mut agent = Agent::start(
        200,
        r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32001,"message":"Task not found"}}"#,
    )
    .await;
    let s = served(instance, &agent.entry("planner", "1h"), false, None);
    approve(&s, "planner").await;
    for call in 0..6 {
        let (_, body) = answered(
            &s.router,
            rpc("planner", "message/send", SEND, Some(&s.token)),
        )
        .await;
        assert!(
            !body.contains("breaker_open"),
            "call {call}: a protocol error on a 2xx is no fault of the agent's: {body}"
        );
        assert!(agent.relayed(), "call {call} was dialled: {body}");
    }
}

/// What the presenting key's ledger holds, over every lane of its bucket: its admitted requests,
/// the fee units its admissions charged and its ends kept, the bytes ledgered, and its spend.
#[derive(Debug, Clone, Copy)]
struct Billed {
    requests: u64,
    fees: u64,
    bytes: u64,
    spend: i64,
}

impl Billed {
    fn of(s: &Served) -> Self {
        let now = busbar_kernel::store::now();
        let usage = futures::executor::block_on(s.gov.usage_for_async(&s.app.cost, &s.key.id, now))
            .expect("a read")
            .expect("the key exists");
        let lanes = futures::executor::block_on(s.gov.bucket_model_tokens_async(
            &s.key.id,
            busbar_kernel::governance::WINDOW_TOTAL,
            now,
        ))
        .expect("read native metering lanes");
        let sum = |class: &str| -> u64 {
            busbar_contract::Count::total(
                lanes
                    .iter()
                    .map(|(_, units)| units.get(class).copied().unwrap_or_default()),
            )
            .expect("A2A fixture totals fit exactly")
            .whole_u64()
            .expect("A2A byte and fee fixture totals are exact whole units")
        };
        Billed {
            requests: usage.requests,
            fees: sum(busbar_contract::plane::PER_REQUEST),
            bytes: sum(surface("bytes_class")),
            spend: usage.spend_cents,
        }
    }
}

/// R2 (ruled; the kernel owns metering): A HOP THE BREAKER REFUSED COUNTS ITS REQUEST AND BILLS
/// NO FEE, NO BYTES AND NO SPEND.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_hop_the_breaker_refused_counts_its_request_and_bills_no_fee_no_bytes_no_spend() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-breaker-billed";
    let mut agent = Agent::start(503, r#"{"error":"down"}"#).await;
    let s = served(instance, &agent.entry("planner", "1h"), false, None);
    approve(&s, "planner").await;
    let mut reached = false;
    for call in 0..32 {
        let before = Billed::of(&s);
        let (_, body) = answered(
            &s.router,
            rpc("planner", "message/send", SEND, Some(&s.token)),
        )
        .await;
        let dialled = agent.relayed();
        let after = Billed::of(&s);
        if body.contains("breaker_open") {
            assert!(reached, "the RED arm ran first: a hop reached the agent");
            assert!(!dialled, "the refused hop never dialled: {body}");
            assert_eq!(
                after.requests - before.requests,
                1,
                "the refused hop's request is counted: {before:?} -> {after:?}"
            );
            assert_eq!(
                after.fees, before.fees,
                "the refused hop bills no fee: {before:?} -> {after:?}"
            );
            assert_eq!(
                after.bytes, before.bytes,
                "the refused hop bills no bytes: {before:?} -> {after:?}"
            );
            assert_eq!(
                after.spend, before.spend,
                "the refused hop spends nothing: {before:?} -> {after:?}"
            );
            return;
        }
        if dialled && !reached {
            assert_eq!(
                after.requests - before.requests,
                1,
                "call {call}: {before:?} -> {after:?}"
            );
            assert_eq!(
                after.fees - before.fees,
                1,
                "call {call}: a hop that reached the agent keeps its fee: {before:?} -> {after:?}"
            );
            assert!(
                after.bytes > before.bytes,
                "call {call}: a hop that reached the agent bills its bytes: {before:?} -> {after:?}"
            );
            reached = true;
        }
    }
    panic!("the breaker opened within 32 failing calls");
}

/// The bytes of the request body the far agent was sent, read off its `heard` text.
fn body_bytes(heard: &str) -> u64 {
    heard
        .split_once("\r\n\r\n")
        .map_or(0, |(_, b)| b.len() as u64)
}

/// **N REQUEST BYTES + M RESPONSE BYTES LEDGER N+M `bytes`**, and with no `agents.rate_card` at
/// all that count prices at 0 and nothing refuses: a group `budget:` of one minor unit is never
/// tripped by it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_hop_ledgers_its_request_and_response_body_bytes_and_no_card_reads_zero() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-bytes-no-card";
    let mut agent = Agent::start(200, ANSWER).await;
    let priced = Priced {
        bytes_rate: None,
        fee: 0,
        budget: 1,
    };
    let s = served_priced(instance, &agent.entry("planner", "1h"), &priced);
    approve(&s, "planner").await;
    let mut moved = 0u64;
    for n in 1..=3 {
        let (status, body) = answered(
            &s.router,
            rpc("planner", "message/send", SEND, Some(&s.token)),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "call {n}: billing off serves every call: {body}"
        );
        let heard = agent.heard.recv().await.expect("the far agent was dialled");
        moved += body_bytes(&heard) + ANSWER.len() as u64;
    }
    assert!(moved > 3 * ANSWER.len() as u64, "the hops carried bodies");
    let billed = Billed::of(&s);
    assert_eq!(
        billed.bytes, moved,
        "three hops ledger their request bodies plus the agent's answers verbatim: {billed:?}"
    );
    assert_eq!(
        billed.spend, 0,
        "no card: billing is off and the counts price at 0, never refused: {billed:?}"
    );
}

/// **AN `agents.rate_card` PRICES THE BYTES, AND A BUDGET CAP TRIPS ON AGENT TRAFFIC.** One
/// minor unit a byte: the first hop's N+M bytes read as N+M minor units, and the second
/// submission is refused at the door on the budget the bytes spent (`429`), without dialling.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_agents_card_prices_the_bytes_and_a_budget_cap_trips() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-bytes-priced";
    let mut agent = Agent::start(200, ANSWER).await;
    let priced = Priced {
        bytes_rate: Some(10_000),
        fee: 0,
        budget: 1,
    };
    let s = served_priced(instance, &agent.entry("planner", "1h"), &priced);
    approve(&s, "planner").await;
    let (status, body) = answered(
        &s.router,
        rpc("planner", "message/send", SEND, Some(&s.token)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "call 1 is under the cap: {body}");
    let heard = agent.heard.recv().await.expect("the far agent was dialled");
    let moved = body_bytes(&heard) + ANSWER.len() as u64;
    let billed = Billed::of(&s);
    assert_eq!(billed.bytes, moved, "{billed:?}");
    assert_eq!(
        billed.spend,
        i64::try_from(moved).expect("small"),
        "{moved} bytes x 10,000 micro-units = {moved} minor units: {billed:?}"
    );
    let (status, body) = answered(
        &s.router,
        rpc("planner", "message/send", SEND, Some(&s.token)),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "call 2 trips the budget the card priced: {body}"
    );
    assert!(body.contains("budget"), "{body}");
    assert!(!agent.relayed(), "the refused call never left");
}

/// **`agents.fees.per_request` CHARGES ONCE PER SERVED HOP.** Each hop is admitted under the
/// plane's pool, one fee unit on its fee lane, so a fee of 2 reads 2 x 3 = 6 over three hops.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn agents_fees_per_request_charges_once_per_served_hop() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-fee-charges";
    let agent = Agent::start(200, ANSWER).await;
    let priced = Priced {
        bytes_rate: None,
        fee: 2,
        budget: 1_000,
    };
    let s = served_priced(instance, &agent.entry("planner", "1h"), &priced);
    approve(&s, "planner").await;
    for n in 1..=3 {
        let (status, body) = answered(
            &s.router,
            rpc("planner", "message/send", SEND, Some(&s.token)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "call {n}: {body}");
    }
    let billed = Billed::of(&s);
    assert_eq!(billed.fees, 3, "one fee unit per hop: {billed:?}");
    assert_eq!(
        billed.spend, 6,
        "three hops at agents.fees.per_request 2: {billed:?}"
    );
}

/// **A HOP REFUSED BEFORE THE SOCKET KEEPS NO FEE.** At `agents.fees.per_request: 2`, every hop
/// that reaches the failing agent keeps its fee of 2.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_hop_refused_before_the_socket_keeps_no_fee() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-refused-no-fee";
    let mut agent = Agent::start(503, r#"{"error":"down"}"#).await;
    let priced = Priced {
        bytes_rate: None,
        fee: 2,
        budget: 1_000,
    };
    let s = served_priced(instance, &agent.entry("planner", "1h"), &priced);
    approve(&s, "planner").await;
    let mut left = 0u64;
    let mut tripped = false;
    for _ in 0..32 {
        let (_, body) = answered(
            &s.router,
            rpc("planner", "message/send", SEND, Some(&s.token)),
        )
        .await;
        if agent.relayed() {
            left += 1;
        }
        if body.contains("breaker_open") {
            tripped = true;
            break;
        }
    }
    assert!(tripped, "the breaker opened within 32 failing calls");
    assert!(left >= 1, "the control hop reached the dying agent");
    for n in 1..=3 {
        let (_, body) = answered(
            &s.router,
            rpc("planner", "message/send", SEND, Some(&s.token)),
        )
        .await;
        assert!(
            body.contains("breaker_open"),
            "call {n} is refused by the open breaker: {body}"
        );
        assert!(!agent.relayed(), "call {n} never left");
    }
    let billed = Billed::of(&s);
    assert_eq!(
        billed.fees, left,
        "only the hops that left keep a fee unit: {billed:?}"
    );
    assert_eq!(
        billed.spend,
        2 * i64::try_from(left).expect("small"),
        "the hops that left keep their fees of 2; the refused ones keep none: {billed:?}"
    );
}

/// B2 (restored, #42, #77(5)): A PRESENT AGENTS CARD SILENT ABOUT AN AGENT REFUSES THE CONFIG,
/// at boot and on every apply.
#[test]
fn a_present_agents_card_silent_about_an_agent_refuses_the_config() {
    let _one = PUBLISHING.blocking_lock();
    crate::dist_root_install::install();
    let (section, kind) = (surface("section"), surface("resource_kind"));
    let resolved = |card: &str| {
        let text = format!(
            "store: {{module: memory}}\nproviders: {{}}\nmodels: {{}}\n{section}:\n  \
             planner: {{ url: https://planner.example/rpc, pin: {{ mechanism: unpinned }} }}\n  \
             payments: {{ url: https://payments.example/rpc, pin: {{ mechanism: unpinned }} }}\n  \
             rate_card:\n{card}"
        );
        let deploy = busbar_kernel::config::deploy_from_yaml_str(&text).expect("the config parses");
        busbar_kernel::config::resolve(&deploy, &Default::default()).expect("resolves")
    };
    let silent = resolved(&format!(
        "    {kind}:payments: {{ units: {{ bytes: 10000 }} }}\n"
    ));
    assert_eq!(
        busbar_kernel::config_validate::validate(&silent),
        Err(vec![format!(
            "{section}.rate_card is present but 1 {noun} has no rate entry (a present card is \
             AUTHORITATIVE and COMPLETE: you either price nothing or price everything).\n\
             Paste these under {section}.rate_card and fill in your rates:\n\n    \
             {kind}:planner: {{ units: {{ bytes: 0 }} }}\n",
            noun = surface("subject_noun"),
        )]),
        "a card silent about `planner` refuses before any hop to it can be ledgered"
    );
    let complete = resolved(&format!(
        "    {kind}:payments: {{ units: {{ bytes: 10000 }} }}\n    \
         {kind}:planner: {{ units: {{ bytes: 0 }} }}\n"
    ));
    assert_eq!(
        busbar_kernel::config_validate::validate(&complete),
        Ok(()),
        "a card pricing every agent boots"
    );
}

/// The root cell `egress-auth × a2a-client`: the agent is handed only the credential the egress
/// plans for its member — none is configured here — and never the caller's own token, which
/// authenticated the caller to busbar and stops there.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_relayed_agent_unit_never_hands_the_agent_the_callers_token() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-egress-auth";
    let mut agent = Agent::start(200, ANSWER).await;
    let s = served(instance, &agent.entry("planner", "1h"), false, None);
    approve(&s, "planner").await;
    let (status, body) = answered(
        &s.router,
        rpc("planner", "message/send", SEND, Some(&s.token)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "relayed through the door: {body}");
    let head = agent.heard.recv().await.expect("the far agent was dialled");
    assert!(
        !head.contains(&s.token),
        "the caller's token never leaves busbar: {head}"
    );
    assert!(
        !head
            .lines()
            .any(|l| l.to_ascii_lowercase().starts_with("authorization:")),
        "no credential is planned for this member, so none is presented: {head}"
    );
}

/// A GET of `path` on the admin router, under the operator credential: its status and body.
async fn admin_get(s: &Served, path: &str) -> (StatusCode, serde_json::Value) {
    let req = axum::http::Request::builder()
        .method("GET")
        .uri(format!("/api/v1/admin{path}"))
        .header("x-admin-token", ADMIN_TOKEN)
        .body(axum::body::Body::empty())
        .expect("a request");
    let (status, text) = answered(&s.admin, req).await;
    let body = serde_json::from_str(&text).unwrap_or(serde_json::Value::String(text));
    (status, body)
}

/// Agent `name`'s trust key on the kernel's trust book, as `GET /trust` lists it
/// (`<instance>/<agent>`), and its state.
async fn trust_key(s: &Served, name: &str) -> (String, String) {
    let (status, book) = admin_get(s, "/trust").await;
    assert_eq!(status, StatusCode::OK, "{book}");
    let row = book["keys"]
        .as_array()
        .and_then(|keys| {
            keys.iter()
                .find(|k| k["counterparty"] == name && k["item"].is_null())
        })
        .unwrap_or_else(|| panic!("the trust book lists no key for `{name}`: {book}"));
    (
        row["key"].as_str().unwrap_or_default().to_string(),
        row["state"].as_str().unwrap_or_default().to_string(),
    )
}

/// One POST to `/api/v1/admin{path}` with a JSON body, under the operator credential.
async fn admin(s: &Served, path: &str, body: &str) -> (StatusCode, serde_json::Value) {
    let req = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/api/v1/admin{path}"))
        .header("x-admin-token", ADMIN_TOKEN)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body.to_string()))
        .expect("a request");
    let (status, text) = answered(&s.admin, req).await;
    let body = serde_json::from_str(&text).unwrap_or(serde_json::Value::String(text));
    (status, body)
}

/// The agent card `port` serves, its one skill described as `description`.
fn card(port: u16, description: &str) -> serde_json::Value {
    serde_json::json!({
        "name": "planner",
        "description": "plans the work it is given",
        "url": format!("http://127.0.0.1:{port}/planner"),
        "supportedInterfaces": [{
            "url": format!("http://127.0.0.1:{port}/planner"),
            "protocolBinding": "JSONRPC",
            "protocolVersion": "1.0",
        }],
        "version": "1.0.0",
        "capabilities": {},
        "defaultInputModes": ["text/plain"],
        "defaultOutputModes": ["text/plain"],
        "skills": [{"id": "plan", "name": "Plan", "description": description, "tags": ["plan"]}],
    })
}

/// `card` signed by `issuer` as an A2A card is signed: one detached EdDSA signature over the
/// canonical card with its `signatures` member removed.
fn signed(card: &serde_json::Value, issuer: &ed25519_dalek::SigningKey) -> serde_json::Value {
    use base64::Engine as _;
    use ed25519_dalek::Signer as _;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let payload = signing_payload(card);
    let protected = b64.encode(br#"{"alg":"EdDSA"}"#);
    let signature = issuer.sign(format!("{protected}.{}", b64.encode(payload)).as_bytes());
    let mut signed = card.clone();
    signed["signatures"] = serde_json::json!([
        {"protected": protected, "signature": b64.encode(signature.to_bytes())}
    ]);
    signed
}

/// `issuer`'s public key as the operator pins it: base64 Ed25519 SubjectPublicKeyInfo.
fn key_info(issuer: &ed25519_dalek::SigningKey) -> String {
    use base64::Engine as _;

    let mut der = vec![
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    der.extend_from_slice(issuer.verifying_key().as_bytes());
    base64::engine::general_purpose::STANDARD.encode(der)
}

/// AN AGENT ON LOOPBACK PINNED BY ITS SIGNING KEY: it serves the card `card` holds (signed when it
/// is asked by the key `signing` holds) at its origin's well-known path.
struct Agent {
    port: u16,
    heard: tokio::sync::mpsc::UnboundedReceiver<String>,
    card: Arc<std::sync::Mutex<serde_json::Value>>,
    issuer: ed25519_dalek::SigningKey,
    /// The key the served card is signed with when it is fetched: `issuer` unless swapped.
    signing: Arc<std::sync::Mutex<ed25519_dalek::SigningKey>>,
    fetches: Arc<std::sync::atomic::AtomicUsize>,
    accepted: Arc<std::sync::atomic::AtomicUsize>,
    down: Arc<std::sync::atomic::AtomicBool>,
    /// `0`: the card is served at the well-known path; `1`: the well-known path redirects to
    /// `/cards/card.json`, which serves it; `2` to `5` select further redirect behaviours.
    redirect: Arc<std::sync::atomic::AtomicU8>,
    /// How long the next card fetch takes to answer (the ones after it answer at once).
    card_delay_ms: Arc<std::sync::atomic::AtomicU64>,
}

impl Agent {
    /// An agent answering every relayed request `status` with `answer`, its card describing
    /// its one skill as "plans the work".
    async fn start(status: u16, answer: &'static str) -> Self {
        Self::start_over(status, answer, None).await
    }

    /// [`Agent::start`], its connections secured by `tls` when given.
    async fn start_over(
        status: u16,
        answer: &'static str,
        tls: Option<tokio_rustls::TlsAcceptor>,
    ) -> Self {
        Self::start_with(status, answer, Vec::new(), tls).await
    }

    /// [`Agent::start_over`], each relayed request answered with the head fields `fields`
    /// beside its status and body.
    async fn start_with(
        status: u16,
        answer: &'static str,
        fields: Vec<(&'static str, String)>,
        tls: Option<tokio_rustls::TlsAcceptor>,
    ) -> Self {
        Self::start_core(
            Arc::new(move |_: &str| status),
            Arc::new(move |_: &str| answer.to_string()),
            fields,
            tls,
        )
        .await
    }

    /// An agent answering each relayed request `status` with what `answer_of` makes of the
    /// request (its whole text), its card describing its one skill as "plans the work".
    async fn start_answering(
        status: u16,
        answer_of: Arc<dyn Fn(&str) -> String + Send + Sync>,
    ) -> Self {
        Self::start_answering_over(status, answer_of, None).await
    }

    /// [`Agent::start_answering`], its connections secured by `tls` when given.
    async fn start_answering_over(
        status: u16,
        answer_of: Arc<dyn Fn(&str) -> String + Send + Sync>,
        tls: Option<tokio_rustls::TlsAcceptor>,
    ) -> Self {
        Self::start_core(Arc::new(move |_: &str| status), answer_of, Vec::new(), tls).await
    }

    /// The agent every constructor starts: each relayed request answered at the status
    /// `status_of` makes of it with what `answer_of` makes of it and the head fields `fields`,
    /// its connections secured by `tls`.
    async fn start_core(
        status_of: Arc<dyn Fn(&str) -> u16 + Send + Sync>,
        answer_of: Arc<dyn Fn(&str) -> String + Send + Sync>,
        fields: Vec<(&'static str, String)>,
        tls: Option<tokio_rustls::TlsAcceptor>,
    ) -> Self {
        Self::start_replying(
            Arc::new(move |request| FarReply {
                fields: fields.clone(),
                ..FarReply::of(status_of(request), answer_of(request))
            }),
            tls,
        )
        .await
    }

    /// One complete status/body decision per relayed request, excluding card fetches.
    async fn start_replying(
        reply_of: Arc<dyn Fn(&str) -> FarReply + Send + Sync>,
        tls: Option<tokio_rustls::TlsAcceptor>,
    ) -> Self {
        use std::sync::atomic::Ordering;
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let card = Arc::new(std::sync::Mutex::new(serde_json::Value::Null));
        let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let fetches = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let down = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let redirect = Arc::new(std::sync::atomic::AtomicU8::new(0));
        let card_delay_ms = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let signing = Arc::new(std::sync::Mutex::new(issuer.clone()));
        let (served, signer, counted, off, moved, slow) = (
            Arc::clone(&card),
            Arc::clone(&signing),
            Arc::clone(&fetches),
            Arc::clone(&down),
            Arc::clone(&redirect),
            Arc::clone(&card_delay_ms),
        );
        let (port, heard) = far_end_observed(
            Arc::new(move |request: &str| {
                if off.load(Ordering::SeqCst) {
                    return None;
                }
                if request.starts_with("GET ") {
                    let to = |location: &str| FarReply {
                        status: 302,
                        fields: vec![("location", location.to_string())],
                        body: String::new(),
                        delay_ms: 0,
                    };
                    match moved.load(Ordering::SeqCst) {
                        2 => return Some(to("/loop")),
                        3 => {
                            return Some(to(
                                "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                            ))
                        }
                        4 => {
                            return Some(to("http://metadata.google.internal/computeMetadata/v1/"))
                        }
                        1 if request.starts_with(CARD_PATH) => return Some(to("/cards/card.json")),
                        5 if request.starts_with(CARD_PATH) => return Some(to("/cards/one")),
                        5 if request.starts_with("GET /cards/one ") => {
                            return Some(to("/cards/card.json"))
                        }
                        _ => {}
                    }
                    counted.fetch_add(1, Ordering::SeqCst);
                    let card = served.lock().map(|c| c.clone()).unwrap_or_default();
                    let key = signer.lock().expect("the signing key").clone();
                    return Some(FarReply {
                        delay_ms: slow.swap(0, Ordering::SeqCst),
                        ..FarReply::of(200, signed(&card, &key).to_string())
                    });
                }
                Some(reply_of(request))
            }),
            tls,
            Some(Arc::clone(&accepted)),
        )
        .await;
        *card.lock().expect("the card") = self::card(port, "plans the work");
        Self {
            port,
            heard,
            card,
            issuer,
            signing,
            fetches,
            accepted,
            down,
            redirect,
            card_delay_ms,
        }
    }

    /// The card it serves now, as the operator's `connect` reads it: its fingerprint.
    fn fingerprint(&self) -> String {
        let card = self.card.lock().expect("the card").clone();
        card_fingerprint(&signed(&card, &self.issuer))
    }

    /// Its card re-issued under the same key with its one skill described as `description`.
    fn reissue(&self, description: &str) {
        *self.card.lock().expect("the card") = card(self.port, description);
    }

    /// Its card, the same content, signed from now on by `key` (a look-alike's key, never the
    /// issuer key the operator pinned).
    fn resign_with(&self, key: ed25519_dalek::SigningKey) {
        *self.signing.lock().expect("the signing key") = key;
    }

    /// How many times its card was fetched.
    fn fetches(&self) -> usize {
        self.fetches.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn accepted(&self) -> usize {
        self.accepted.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// It stops answering.
    fn go_down(&self) {
        self.down.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Whether it was sent a relayed request since it was last asked.
    fn relayed(&mut self) -> bool {
        let mut relayed = false;
        while self.heard.try_recv().is_ok() {
            relayed = true;
        }
        relayed
    }

    /// The `agents:` entry registering `name` at this agent's path `/<name>`, pinned by its
    /// signing key, re-verified within `reverify_ttl`.
    fn entry(&self, name: &str, reverify_ttl: &str) -> String {
        self.entry_with(name, reverify_ttl, "")
    }

    /// [`Agent::entry`] with `more` (`key: value` pairs, comma-separated) added to it.
    fn entry_with(&self, name: &str, reverify_ttl: &str, more: &str) -> String {
        let more = if more.is_empty() {
            String::new()
        } else {
            format!(", {more}")
        };
        format!(
            "{name}: {{url: 'http://127.0.0.1:{}/{name}', allow_private: true, reverify_ttl: \
             '{reverify_ttl}', pin: {{mechanism: jws_issuer_key, key: '{}'}}{more}}}",
            self.port,
            key_info(&self.issuer)
        )
    }

    /// Its card from now on declares that it answers in events (`capabilities.streaming`).
    fn streams(&self) {
        let mut card = self.card.lock().expect("the card");
        card["capabilities"] = serde_json::json!({ "streaming": true });
    }
}

impl Agent {
    /// The `agents:` entry registering `name` at this agent's SECURE path `/<name>`, pinned at
    /// the transport by `mechanism` to the far end's key `key`, re-verified within an hour.
    fn entry_pinned(&self, name: &str, mechanism: &str, key: &str) -> String {
        format!(
            "{name}: {{url: 'https://127.0.0.1:{}/{name}', allow_private: true, reverify_ttl: \
             '1h', pin: {{mechanism: {mechanism}, key: '{key}'}}}}",
            self.port
        )
    }
}

/// The server key a TLS agent presents, swappable under it.
type ServingKey = Arc<std::sync::Mutex<Arc<rustls::sign::CertifiedKey>>>;

/// A TLS agent's server certificate resolver: whatever key it is serving now.
#[derive(Debug)]
struct Serving(ServingKey);

impl rustls::server::ResolvesServerCert for Serving {
    fn resolve(
        &self,
        _: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(Arc::clone(&self.0.lock().expect("the key")))
    }
}

/// A TEST ROOT FOR LOOPBACK TLS AGENTS: the root's DER (the connector is told to trust it), the
/// issuer of each leaf, and the key the agent serves now.
struct AgentTls {
    root: Vec<u8>,
    issuer: rcgen::Issuer<'static, rcgen::KeyPair>,
    serving: ServingKey,
}

impl AgentTls {
    fn new() -> Self {
        busbar_core_connector::tls::install_crypto_provider();
        let kp = rcgen::KeyPair::generate().expect("a key");
        let mut params = rcgen::CertificateParams::new(Vec::new()).expect("params");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let root = params.self_signed(&kp).expect("the root").der().to_vec();
        let issuer = rcgen::Issuer::new(params, kp);
        let (first, _) = Self::issue(&issuer);
        Self {
            root,
            issuer,
            serving: Arc::new(std::sync::Mutex::new(first)),
        }
    }

    /// A fresh leaf for `127.0.0.1` under the root: the key it is served with, and its key's
    /// pin, taken off the key pair itself.
    fn issue(
        issuer: &rcgen::Issuer<'static, rcgen::KeyPair>,
    ) -> (Arc<rustls::sign::CertifiedKey>, String) {
        use rcgen::PublicKeyData as _;
        let kp = rcgen::KeyPair::generate().expect("a key");
        let mut params = rcgen::CertificateParams::new(Vec::new()).expect("params");
        params.subject_alt_names = vec![rcgen::SanType::IpAddress(std::net::IpAddr::V4(
            std::net::Ipv4Addr::LOCALHOST,
        ))];
        let leaf = params.signed_by(&kp, issuer).expect("the leaf");
        let key = rustls::sign::CertifiedKey::from_der(
            vec![leaf.der().clone()],
            rustls_pki_types::PrivateKeyDer::try_from(kp.serialize_der()).expect("a key"),
            &rustls::crypto::ring::default_provider(),
        )
        .expect("a certified key");
        (
            Arc::new(key),
            busbar_contract::transport::trust::key_pin(&kp.subject_public_key_info()),
        )
    }

    /// A new key under the root, served from now on: its pin.
    fn rekey(&self) -> String {
        let (key, pin) = Self::issue(&self.issuer);
        *self.serving.lock().expect("the key") = key;
        pin
    }

    /// The acceptor serving whatever key is current, and REQUIRING a client certificate that
    /// chains to `client_root` (a DER root): a mutual-TLS peer that admits one client CA only.
    fn mutual_acceptor(&self, client_root: &[u8]) -> tokio_rustls::TlsAcceptor {
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(rustls_pki_types::CertificateDer::from(client_root.to_vec()))
            .expect("a client root");
        let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .expect("a client verifier");
        let config = rustls::ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_cert_resolver(Arc::new(Serving(Arc::clone(&self.serving))));
        tokio_rustls::TlsAcceptor::from(Arc::new(config))
    }

    /// The acceptor serving whatever key is current.
    fn acceptor(&self) -> tokio_rustls::TlsAcceptor {
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(Serving(Arc::clone(&self.serving))));
        tokio_rustls::TlsAcceptor::from(Arc::new(config))
    }
}

/// A certificate-SPKI agent is served after approval and refused once its key changes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cert_spki_agent_is_observed_approved_served_and_refused_once_its_key_changes() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-door-spki";
    let tls = AgentTls::new();
    let pin = tls.rekey();
    let mut agent = Agent::start_over(200, ANSWER, Some(tls.acceptor())).await;
    let section = agent.entry_pinned("planner", "cert_spki", &pin);
    let s = served_trusting(instance, &section, false, None, Some(tls.root.clone()));

    let (status, preview) = admin(&s, "/agents/planner/connect", "").await;
    assert_eq!(status, StatusCode::OK, "{preview}");
    assert_eq!(preview["state"], "pending", "{preview}");
    assert_eq!(preview["pin_mechanism"], "cert_spki", "{preview}");
    assert_eq!(preview["failure"], serde_json::Value::Null, "{preview}");
    assert_eq!(
        preview["fingerprint"],
        agent.fingerprint().as_str(),
        "{preview}"
    );
    approve(&s, "planner").await;
    let send = || rpc("planner", "message/send", SEND, Some(&s.token));
    let (status, body) = answered(&s.router, send()).await;
    assert_eq!(status, StatusCode::OK, "the pinned agent is served: {body}");
    assert!(body.contains("m-far"), "the far agent's answer: {body}");
    assert!(agent.relayed(), "the pinned agent was dialled");

    let card_fetches = agent.fetches();
    let served_now = tls.rekey();
    assert_ne!(served_now, pin, "the far end now serves a different key");
    let (status, body) = answered(&s.router, send()).await;
    assert_ne!(status, StatusCode::OK, "another key is refused: {body}");
    assert!(
        !agent.relayed(),
        "no request byte reached the agent serving another key"
    );
    let (status, preview) = admin(&s, "/agents/planner/connect", "").await;
    assert_eq!(status, StatusCode::OK, "{preview}");
    assert_eq!(preview["state"], "error", "{preview}");
    assert_eq!(
        agent.fetches(),
        card_fetches,
        "the changed SPKI is refused before any card request reaches the peer"
    );
    assert_eq!(
        preview["failure"],
        format!(
            "agent card fetch of `https://127.0.0.1:{}/.well-known/agent.json` failed: \
             client error (Connect): tls: the far end's key is not the one its trust anchors pin; \
             refused before any request byte",
            agent.port
        )
        .as_str(),
        "{preview}"
    );
}

/// Connect and approve the named agent through the administrative trust endpoints.
async fn approve(s: &Served, name: &str) {
    let (status, preview) = admin(s, &format!("/agents/{name}/connect"), "").await;
    assert_eq!(status, StatusCode::OK, "{preview}");
    let fingerprint = preview["fingerprint"]
        .as_str()
        .unwrap_or_else(|| panic!("connect reported no fingerprint: {preview}"))
        .to_string();
    let (status, approved) = admin(
        s,
        &format!("/agents/{name}/approve"),
        &format!(r#"{{"fingerprint": "{fingerprint}"}}"#),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{approved}");
    assert_eq!(approved["state"], "approved", "{approved}");
}

/// Decide agent `name`'s trust key on the generic `/trust` (`approve` or `revoke`), at what it
/// was last sighted at.
async fn decide_key(s: &Served, name: &str, decision: &str) -> (StatusCode, serde_json::Value) {
    let (key, _) = trust_key(s, name).await;
    let body = serde_json::json!({ "key": key }).to_string();
    admin(s, &format!("/trust/{decision}"), &body).await
}

/// The root cells `trust-pinning × a2a-client` and `trust-pinning × a2a-server`, on the KERNEL'S
/// trust book (the plane sights, the kernel pins, quarantines and keeps the operator's decision).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_kernel_trust_book_pins_an_agent_card_and_the_relay_serves_only_the_approved_one() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-trust";
    let mut agent = Agent::start(200, ANSWER).await;
    let fingerprint = agent.fingerprint();
    let scout = "allow_private: true, pin: {mechanism: unpinned}";
    let section = format!(
        "{}\nscout: {{url: 'http://127.0.0.1:{}/scout', {scout}}}",
        agent.entry("planner", "0s"),
        agent.port
    );
    let s = served(instance, &section, false, None);
    let send = |to: &str| rpc(to, "message/send", SEND, Some(&s.token));
    let untrusted = |status: StatusCode, body: &str, agent: &str, state: &str| {
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        let doc: serde_json::Value = serde_json::from_str(body).expect("an envelope");
        assert_eq!(doc["error"]["code"], -32004, "{body}");
        assert_eq!(
            doc["error"]["message"],
            format!("fronted agent `{agent}` is not serving ({state})"),
            "{body}"
        );
    };

    let (status, body) = answered(&s.router, send("planner")).await;
    untrusted(status, &body, "planner", "Pending");
    assert!(!agent.relayed(), "a refused unit is never dialled");

    let (status, preview) = admin(&s, "/agents/planner/connect", "").await;
    assert_eq!(status, StatusCode::OK, "{preview}");
    assert_eq!(
        preview["state"], "pending",
        "a preview grants nothing: {preview}"
    );
    assert_eq!(preview["pin_mechanism"], "jws_issuer_key", "{preview}");
    assert_eq!(preview["fingerprint"], fingerprint.as_str(), "{preview}");
    assert_eq!(preview["failure"], serde_json::Value::Null, "{preview}");
    assert_eq!(
        agent.fetches(),
        1,
        "the card was fetched at the well-known path"
    );
    let (_, state) = trust_key(&s, "planner").await;
    assert_eq!(state, "new", "the sighting is new until approved");
    let (status, body) = answered(&s.router, send("planner")).await;
    untrusted(status, &body, "planner", "Pending");
    assert!(!agent.relayed(), "a refused unit is never dialled");

    let (status, approved) = admin(
        &s,
        "/agents/planner/approve",
        &format!(r#"{{"fingerprint": "{fingerprint}"}}"#),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{approved}");
    assert_eq!(approved["state"], "approved", "{approved}");
    assert_eq!(approved["fingerprint"], fingerprint.as_str(), "{approved}");
    let fetched = agent.fetches();
    let (status, body) = answered(&s.router, send("planner")).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the approved agent is served: {body}"
    );
    assert!(body.contains("m-far"), "the far agent's answer: {body}");
    assert!(agent.relayed(), "the approved agent was dialled");
    assert!(
        agent.fetches() > fetched,
        "its card was re-verified on call"
    );

    let (status, revoked) = decide_key(&s, "planner", "revoke").await;
    assert_eq!(status, StatusCode::OK, "{revoked}");
    let (status, body) = answered(&s.router, send("planner")).await;
    untrusted(status, &body, "planner", "Pending");
    assert!(!agent.relayed(), "a revoked agent is never dialled");
    let (status, reapproved) = decide_key(&s, "planner", "approve").await;
    assert_eq!(status, StatusCode::OK, "{reapproved}");
    let (status, body) = answered(&s.router, send("planner")).await;
    assert_eq!(status, StatusCode::OK, "approved on /trust, served: {body}");
    assert!(agent.relayed(), "dialled again");

    agent.reissue("plans the work and forwards it on");
    let fetched = agent.fetches();
    let (status, body) = answered(&s.router, send("planner")).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    let doc: serde_json::Value = serde_json::from_str(&body).expect("an envelope");
    assert_eq!(doc["error"]["code"], -32004, "{body}");
    assert_eq!(
        doc["error"]["message"], "this agent is not currently serving",
        "{body}"
    );
    assert!(
        doc["error"]["data"].as_array().is_some_and(|d| d
            .iter()
            .any(|e| e["resourceType"] == surface("task_resource_type"))),
        "the refusal names its task: {body}"
    );
    assert!(
        agent.fetches() > fetched,
        "the drift was found by a live re-fetch"
    );
    assert!(!agent.relayed(), "a demoted agent is never dialled");

    agent.reissue("plans the work");
    let (status, body) = answered(&s.router, send("planner")).await;
    untrusted(status, &body, "planner", "Quarantined");
    assert!(!agent.relayed(), "a quarantined agent is never dialled");
    agent.reissue("plans the work and forwards it on");
    let (status, drifted) = admin(&s, "/agents/planner/connect", "").await;
    assert_eq!(status, StatusCode::OK, "{drifted}");
    assert_eq!(drifted["state"], "quarantined", "{drifted}");
    assert_ne!(drifted["fingerprint"], fingerprint.as_str(), "{drifted}");

    let (_, state) = trust_key(&s, "planner").await;
    assert_eq!(state, "drifted", "the book holds the quarantine");
    let (status, stale) = admin(
        &s,
        "/agents/planner/approve",
        &format!(r#"{{"fingerprint": "{fingerprint}"}}"#),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{stale}");
    assert_eq!(stale["error"]["code"], "invalid_request", "{stale}");
    approve(&s, "planner").await;
    let (status, body) = answered(&s.router, send("planner")).await;
    assert_eq!(status, StatusCode::OK, "re-approved, it is served: {body}");

    let (status, captured) = admin(&s, "/agents/scout/connect", "").await;
    assert_eq!(status, StatusCode::OK, "{captured}");
    assert_eq!(captured["state"], "pending", "{captured}");
    assert_eq!(captured["pin_mechanism"], "unpinned", "{captured}");
    assert_eq!(
        captured["fingerprint"],
        serde_json::Value::Null,
        "{captured}"
    );
    let (status, capped) = admin(
        &s,
        "/agents/scout/approve",
        r#"{"fingerprint": "sha256:any"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{capped}");
    let (status, unsighted) = decide_key(&s, "scout", "approve").await;
    assert_eq!(status, StatusCode::CONFLICT, "never sighted: {unsighted}");
    let (status, body) = answered(&s.router, send("scout")).await;
    untrusted(status, &body, "scout", "Pending");

    let (status, unknown) = admin(&s, "/agents/nobody/connect", "").await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{unknown}");
    assert_eq!(unknown["error"]["code"], "not_found", "{unknown}");
}

/// THE LOOK-ALIKE, ONCE APPROVED (moved here from busbar's root `qa_a2a.rs`, where it ran the
/// shipped binary against a loopback agent).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_approved_agents_card_resigned_by_another_key_stops_it_being_served() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-lookalike";
    let mut agent = Agent::start(200, ANSWER).await;
    let s = served(instance, &agent.entry("planner", "0s"), false, None);
    approve(&s, "planner").await;
    let send = || rpc("planner", "message/send", SEND, Some(&s.token));

    let (status, body) = answered(&s.router, send()).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the approved agent is served: {body}"
    );
    assert!(body.contains("m-far"), "the far agent's answer: {body}");
    assert!(agent.relayed(), "the approved agent was dialled");

    agent.resign_with(ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]));
    let fetched = agent.fetches();
    let (status, body) = answered(&s.router, send()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    let doc: serde_json::Value = serde_json::from_str(&body).expect("an envelope");
    assert_eq!(doc["error"]["code"], -32004, "{body}");
    assert_eq!(
        doc["error"]["message"], "this agent is not currently serving",
        "{body}"
    );
    assert!(
        agent.fetches() > fetched,
        "the refusal follows a live re-fetch of the card, not a stale memory"
    );
    assert!(
        !agent.relayed(),
        "no request byte reached the agent whose card another key signed"
    );
}

/// SINGLE-FLIGHT VERIFY-ON-CALL (the engine's `VerifyGate`): two units due on one agent at once
/// (`reverify_ttl: 0s`, its card slow to answer) share ONE look at its card and its verdict, and
/// both are served.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_units_due_on_one_agent_share_one_card_look() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-single-flight";
    let agent = Agent::start(200, ANSWER).await;
    let s = served(instance, &agent.entry("planner", "0s"), false, None);
    approve(&s, "planner").await;
    agent
        .card_delay_ms
        .store(300, std::sync::atomic::Ordering::SeqCst);
    let fetched = agent.fetches();
    let send = || rpc("planner", "message/send", SEND, Some(&s.token));
    let ((first, a), (second, b)) =
        tokio::join!(answered(&s.router, send()), answered(&s.router, send()));
    assert_eq!(first, StatusCode::OK, "{a}");
    assert_eq!(second, StatusCode::OK, "{b}");
    assert_eq!(
        agent.fetches() - fetched,
        1,
        "the two due units shared one look at the card"
    );
}

/// THE CARD FETCH'S GUARD AND REDIRECTS, as 1.5.5 fetched a card: a card behind a redirect is
/// followed and approved; a chain past three redirects is refused in 1.5.5's words.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_card_fetch_follows_redirects_and_is_guarded_in_its_1_5_5_words() {
    use std::sync::atomic::Ordering;
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-card-fetch";
    let agent = Agent::start(200, ANSWER).await;
    let section = format!(
        "{}\nscout: {{url: 'https://127.0.0.1:{}/scout', pin: {{mechanism: jws_issuer_key, \
         key: '{}'}}}}",
        agent.entry("planner", "1h"),
        agent.port,
        key_info(&agent.issuer)
    );
    let s = served(instance, &section, false, None);

    agent.redirect.store(1, Ordering::SeqCst);
    approve(&s, "planner").await;

    agent.redirect.store(2, Ordering::SeqCst);
    let (status, looped) = admin(&s, "/agents/planner/connect", "").await;
    assert_eq!(status, StatusCode::OK, "{looped}");
    assert_eq!(looped["state"], "error", "{looped}");
    assert_eq!(
        looped["failure"],
        format!(
            "agent card fetch exceeded 3 redirect(s), still redirecting at \
             `http://127.0.0.1:{}/loop`",
            agent.port
        ),
        "{looped}"
    );

    agent.redirect.store(0, Ordering::SeqCst);
    let accepted = agent.accepted();
    let (status, guarded) = admin(&s, "/agents/scout/connect", "").await;
    assert_eq!(status, StatusCode::OK, "{guarded}");
    assert_eq!(
        guarded["failure"],
        "SSRF guard refused the agent card fetch: host `127.0.0.1` resolved to the internal \
         address 127.0.0.1; set this registration's `allow_private: true` if reaching it is \
         deliberate. A cloud-metadata address is refused whatever that is set to.",
        "{guarded}"
    );
    assert_eq!(
        agent.accepted(),
        accepted,
        "the guard refused before opening a socket to the agent"
    );
}

/// A REDIRECT IS A URL A STRANGER CHOSE, judged from scratch at the hop that names it: a card
/// whose well-known path redirects at a cloud-metadata address or name is refused at that hop.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_card_fetch_redirected_at_cloud_metadata_is_refused_at_the_hop_that_names_it() {
    use std::sync::atomic::Ordering;
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-card-redirect-metadata";
    let agent = Agent::start(200, ANSWER).await;
    let s = served(instance, &agent.entry("planner", "1h"), false, None);
    for (mode, host, words) in [
        (
            3,
            "169.254.169.254",
            "SSRF guard refused the agent card fetch: host `169.254.169.254` resolved to the \
             internal address 169.254.169.254; set this registration's `allow_private: true` \
             if reaching it is deliberate. A cloud-metadata address is refused whatever that \
             is set to.",
        ),
        (
            4,
            "metadata.google.internal",
            "SSRF guard refused the agent card fetch: host `metadata.google.internal` is a \
             cloud-metadata name",
        ),
    ] {
        agent.redirect.store(mode, Ordering::SeqCst);
        let before = s.observed_destinations.decisions().len();
        let (status, view) = admin(&s, "/agents/planner/connect", "").await;
        assert_eq!(status, StatusCode::OK, "{view}");
        assert_eq!(view["state"], "error", "mode {mode}: {view}");
        assert_eq!(view["failure"], words, "mode {mode}: {view}");
        let decisions = s.observed_destinations.decisions();
        let redirects: Vec<_> = decisions[before..]
            .iter()
            .filter(|(target, _)| target.contains(host))
            .collect();
        assert!(
            !redirects.is_empty(),
            "the redirect target reached the real guard: {decisions:?}"
        );
        assert!(
            redirects.iter().all(|(_, admitted)| !admitted),
            "the actual redirect destination was never admitted: {redirects:?}"
        );
        assert!(
            decisions[before..]
                .iter()
                .any(|(target, admitted)| target.contains("127.0.0.1") && *admitted),
            "the origin was admitted before its redirect was refused: {decisions:?}"
        );
    }
    assert_eq!(agent.fetches(), 0, "the card was never obtained");
}

/// A LEGAL CHAIN IS FOLLOWED HOP BY HOP: a card behind two redirects (the well-known path to
/// `/cards/one` to `/cards/card.json`) is fetched, verified and approved, each hop judged and
/// dialled in its own right.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_hop_of_a_legal_chain_is_followed_to_the_card() {
    use std::sync::atomic::Ordering;
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-card-redirect-chain";
    let agent = Agent::start(200, ANSWER).await;
    let s = served(instance, &agent.entry("planner", "1h"), false, None);
    agent.redirect.store(5, Ordering::SeqCst);
    approve(&s, "planner").await;
    assert!(
        agent.fetches() >= 1,
        "the card was obtained at the end of the chain"
    );
}

/// THE CHECK ORDER, as 1.5.5's admission kept it: the caller's grant, then the agent's trust,
/// then its card's fit.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_request_the_card_does_not_fit_is_judged_after_the_trust_gate() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-fit-order";
    let mut agent = Agent::start(200, ANSWER).await;
    let s = served(instance, &agent.entry("planner", "1h"), false, None);
    let fly = r#"{"message":{"kind":"message","messageId":"m-2","role":"user","parts":[{"kind":"text","text":"go"}]},"metadata":{"skill":"fly"}}"#;
    let send = || rpc("planner", "message/send", fly, Some(&s.token));
    let (status, body) = answered(&s.router, send()).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "trust first: {body}");
    assert!(
        body.contains("is not serving (Pending)"),
        "the trust refusal, not the card's fit: {body}"
    );
    approve(&s, "planner").await;
    let (status, body) = answered(&s.router, send()).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "then the card's fit: {body}"
    );
    let doc: serde_json::Value = serde_json::from_str(&body).expect("an envelope");
    assert_eq!(doc["error"]["code"], -32004, "{body}");
    assert_eq!(
        doc["error"]["message"], "this agent's card declares no skill `fly`",
        "{body}"
    );
    assert_eq!(doc["id"], serde_json::Value::Null, "{body}");
    assert!(!agent.relayed(), "an unfit request is never dialled");
}

/// A gate refusal is audited and uncharged; the caller's grant is checked before agent standing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_unit_to_an_agent_that_is_not_serving_is_refused_after_its_grant_and_charges_nothing() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-gate";
    let mut agent = Agent::start(200, ANSWER).await;
    let s = served(instance, &agent.entry("planner", "1h"), false, None);
    for (method, params) in [("message/send", SEND), ("tasks/list", "{}")] {
        let (status, body) =
            answered(&s.router, rpc("planner", method, params, Some(&s.token))).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{method}: {body}");
        let doc: serde_json::Value = serde_json::from_str(&body).expect("an envelope");
        assert_eq!(doc["error"]["code"], -32004, "{body}");
        assert_eq!(
            doc["error"]["message"], "fronted agent `planner` is not serving (Pending)",
            "{body}"
        );
    }
    assert!(!agent.relayed(), "never dialled");
    assert_eq!(admitted(&s), 0, "a refused unit is charged nothing");
    drop(s);

    let ungranted = "serve-agent-door-gate-ungranted";
    let s = served(
        ungranted,
        &agent.entry("planner", "1h"),
        false,
        Some(Vec::new()),
    );
    let (status, body) = answered(
        &s.router,
        rpc("planner", "message/send", SEND, Some(&s.token)),
    )
    .await;
    assert_not_granted(status, &body, "planner");
    assert!(
        !body.contains("is not serving"),
        "the grant is judged first: {body}"
    );
    assert_eq!(admitted(&s), 0, "nothing charged");
}

/// An unaddressed unit routes to the one granted agent that is serving.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unaddressed_unit_is_routed_to_the_one_granted_agent_that_serves() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-scope-trust";
    let mut agent = Agent::start(200, ANSWER).await;
    let section = format!(
        "{}\n{}",
        agent.entry("planner", "1h"),
        agent.entry("scout", "1h")
    );
    let s = served(instance, &section, false, None);
    approve(&s, "planner").await;
    let (status, body) = answered(&s.router, rpc("", "message/send", SEND, Some(&s.token))).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "routed to the one that serves: {body}"
    );
    assert!(body.contains("m-far"), "{body}");
    assert!(agent.relayed(), "the approved agent was dialled");
}

/// A config apply advances the refresh generation while preserving operator approval.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_config_apply_keeps_the_operators_approval() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-apply";
    let mut agent = Agent::start(200, ANSWER).await;
    let s = served(instance, &agent.entry("planner", "1h"), false, None);
    approve(&s, "planner").await;
    let send = || rpc("planner", "message/send", SEND, Some(&s.token));
    let (status, body) = answered(&s.router, send()).await;
    assert_eq!(status, StatusCode::OK, "approved, served: {body}");
    assert!(agent.relayed());

    let apply = async |section: &str| {
        let next = s.applied(
            serde_yaml::from_str(section).expect("the applied section"),
            false,
        );
        assert!(
            !Arc::ptr_eq(&s.app, &next),
            "a distinct serving App is applied"
        );
        s.handle.swap(next).await;
    };
    apply(&format!(
        "{}\n{}",
        agent.entry("planner", "1h"),
        agent.entry("scout", "1h")
    ))
    .await;
    let (status, body) = answered(&s.router, send()).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the approval outlives the apply: {body}; trust: {:?}",
        admin_get(&s, "/trust").await
    );
    assert!(
        agent.relayed(),
        "the retained registration still reaches its agent"
    );

    let mut replacement = Agent::start(200, ANSWER).await;
    apply(&replacement.entry("planner", "1h")).await;
    let (status, body) = answered(&s.router, send()).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "the changed URL needs approval: {body}"
    );
    assert!(body.contains("is not serving"), "{body}");
    assert!(
        !agent.relayed() && !replacement.relayed(),
        "neither URL was dispatched under stale approval"
    );
    let (status, preview) = admin(&s, "/agents/planner/connect", "").await;
    assert_eq!(status, StatusCode::OK, "{preview}");
    assert_eq!(
        preview["fingerprint"],
        replacement.fingerprint(),
        "{preview}"
    );
    assert_ne!(
        preview["fingerprint"],
        agent.fingerprint(),
        "the new URL serves a different signed card"
    );
    assert_eq!(preview["state"], "quarantined", "{preview}");
    let (status, body) = answered(&s.router, send()).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a preview cannot approve the replacement card: {body}"
    );
    assert!(body.contains("is not serving"), "{body}");
    assert!(
        !agent.relayed() && !replacement.relayed(),
        "neither endpoint was dispatched before the replacement card was approved"
    );
    approve(&s, "planner").await;
    let (status, body) = answered(&s.router, send()).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the newly approved URL serves: {body}"
    );
    assert!(replacement.relayed());

    let rotated = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
    let invalid = format!(
        "planner: {{url: 'http://127.0.0.1:{}/planner', allow_private: true, reverify_ttl: '1h', \
         pin: {{mechanism: jws_issuer_key, key: '{}'}}}}\nwork: {{max_live: 0}}",
        replacement.port,
        key_info(&rotated),
    );
    apply(&invalid).await;
    let (status, body) = answered(&s.router, send()).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a failed apply keeps the approved prior issuer and serving generation: {body}"
    );
    assert!(
        replacement.relayed(),
        "the prior approved generation still dispatches"
    );
    replacement.resign_with(rotated.clone());
    let section = format!(
        "planner: {{url: 'http://127.0.0.1:{}/planner', allow_private: true, reverify_ttl: '1h', \
         pin: {{mechanism: jws_issuer_key, key: '{}'}}}}",
        replacement.port,
        key_info(&rotated),
    );
    apply(&section).await;
    let (status, body) = answered(&s.router, send()).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "the changed pin needs approval: {body}"
    );
    assert!(body.contains("is not serving"), "{body}");
    assert!(
        !replacement.relayed(),
        "the new issuer cannot inherit the old approval"
    );
    approve(&s, "planner").await;
    let (status, body) = answered(&s.router, send()).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the newly approved issuer serves: {body}"
    );
    assert!(replacement.relayed());
}

/// Card-fetch refusals preserve the 1.5.5 error text regardless of the deployment's private-address stance.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_card_fetch_is_refused_in_1_5_5_words_whatever_the_deployment_private_stance() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-guard-words";
    let agent = Agent::start(200, ANSWER).await;
    let pin = format!(
        "pin: {{mechanism: jws_issuer_key, key: '{}'}}",
        key_info(&agent.issuer)
    );
    let section = format!(
        "literal: {{url: 'https://127.0.0.1:{port}/literal', {pin}}}\n\
         named: {{url: 'https://localhost:{port}/named', {pin}}}\n\
         nowhere: {{url: 'https://card-host.invalid/nowhere', {pin}}}",
        port = agent.port
    );
    let s = served_under(
        instance,
        &section,
        busbar_kernel::config::Destinations {
            block_private_addresses: false,
            ..Default::default()
        },
        None,
        None,
    );
    let failure = |name: &'static str| {
        let s = &s;
        async move {
            let (status, view) = admin(s, &format!("/agents/{name}/connect"), "").await;
            assert_eq!(status, StatusCode::OK, "{view}");
            assert_eq!(view["state"], "error", "{view}");
            view["failure"].as_str().unwrap_or_default().to_string()
        }
    };
    assert_eq!(
        failure("literal").await,
        "SSRF guard refused the agent card fetch: host `127.0.0.1` resolved to the internal \
         address 127.0.0.1; set this registration's `allow_private: true` if reaching it is \
         deliberate. A cloud-metadata address is refused whatever that is set to."
    );
    assert_eq!(
        failure("named").await,
        "SSRF guard refused the agent card fetch: host `localhost` is a loopback name; set \
         this registration's `allow_private: true` if that is deliberate"
    );
    assert_eq!(
        agent.accepted(),
        0,
        "the guard refused before opening a socket"
    );

    let predev = match tokio::net::lookup_host("card-host.invalid:0").await {
        Ok(_) => panic!("a `.invalid` name never resolves"),
        Err(e) => e.to_string(),
    };
    assert_eq!(
        failure("nowhere").await,
        format!("agent card host `card-host.invalid` did not resolve: {predev}")
    );
}

/// A CARD FETCH WHOSE FAR END CLOSES BEFORE REPLYING, in predev's exact words: its engine's
/// HTTP client named it `client error (SendRequest): connection closed before message completed`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_card_fetch_whose_far_end_closes_unanswered_fails_in_predev_words() {
    use tokio::io::AsyncReadExt;
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-closed-unanswered";
    let agent = Agent::start(200, ANSWER).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a port");
    let port = listener.local_addr().expect("its address").port();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let mut heard = Vec::new();
            let mut buf = [0_u8; 1024];
            while !heard.windows(4).any(|w| w == b"\r\n\r\n") {
                match socket.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => heard.extend_from_slice(&buf[..n]),
                }
            }
            drop(socket);
        }
    });
    let section = format!(
        "silent: {{url: 'http://127.0.0.1:{port}/silent', allow_private: true, pin: \
         {{mechanism: jws_issuer_key, key: '{}'}}}}",
        key_info(&agent.issuer)
    );
    let s = served(instance, &section, false, None);
    let (status, view) = admin(&s, "/agents/silent/connect", "").await;
    assert_eq!(status, StatusCode::OK, "{view}");
    assert_eq!(view["state"], "error", "{view}");
    assert_eq!(
        view["failure"],
        format!(
            "agent card fetch of `http://127.0.0.1:{port}/.well-known/agent.json` failed: \
             client error (SendRequest): connection closed before message completed"
        ),
        "{view}"
    );
}

/// A failed card-fetch connection preserves the recorded client-visible error text.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_card_fetch_to_a_closed_port_fails_in_predev_words() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-closed-port";
    let agent = Agent::start(200, ANSWER).await;
    let closed = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("a port")
        .local_addr()
        .expect("its address")
        .port();
    let refused_here = std::net::TcpStream::connect(("127.0.0.1", closed))
        .expect_err("nothing listens on the closed port")
        .to_string();
    let section = format!(
        "closed: {{url: 'https://127.0.0.1:{closed}/closed', allow_private: true, pin: \
         {{mechanism: jws_issuer_key, key: '{}'}}}}",
        key_info(&agent.issuer)
    );
    let s = served(instance, &section, false, None);
    let (status, view) = admin(&s, "/agents/closed/connect", "").await;
    assert_eq!(status, StatusCode::OK, "{view}");
    assert_eq!(view["state"], "error", "{view}");
    assert_eq!(
        view["failure"],
        format!(
            "agent card fetch of `https://127.0.0.1:{closed}/.well-known/agent.json` failed: \
             client error (Connect): tcp connect error: {refused_here}"
        ),
        "{view}"
    );
}

/// THE AGENT DOOR'S TRUST VERBS' DECLARED ERRORS, driven through the admin router by the door's
/// own `serve` op (ARCHITECT Q-L3B-VERBS), the door published as the root publishes it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_agent_doors_trust_verbs_refuse_in_their_declared_taxonomy() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-verb-errors";
    let closed = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("a port")
        .local_addr()
        .expect("its address")
        .port();
    let issuer = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
    let section = format!(
        "closed: {{url: 'http://127.0.0.1:{closed}/closed', allow_private: true, pin: \
         {{mechanism: jws_issuer_key, key: '{}'}}}}",
        key_info(&issuer)
    );
    let s = served(instance, &section, false, None);
    for path in ["/agents/nope/connect", "/agents/nope/approve"] {
        let (status, body) = admin(&s, path, r#"{"fingerprint": "sha256:aa"}"#).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}: {body}");
        assert_eq!(body["error"]["code"], "not_found", "{path}: {body}");
    }
    let (status, body) = admin(
        &s,
        "/agents/closed/approve",
        r#"{"fingerprint": "sha256:aa", "and": "more"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"]["code"], "invalid_request", "{body}");
    assert!(
        body.to_string().contains("fingerprint"),
        "the malformed-body refusal names the one field the body may carry: {body}"
    );
    let (status, body) = admin(
        &s,
        "/agents/closed/approve",
        r#"{"fingerprint": "sha256:aa"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"]["code"], "invalid_request", "{body}");
    assert!(
        body.to_string().contains("nothing to approve"),
        "the invalid-config refusal says the card could not be authenticated: {body}"
    );
}

/// AN UNREACHABLE CARD AT VERIFY FAILS CLOSED ON THE CALL PATH (the engine's
/// `verify_tests::an_unreachable_card_at_verify_fails_closed_on_the_call_path`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unreachable_card_at_verify_fails_closed_on_the_call_path() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-unreachable-on-call";
    let mut agent = Agent::start(200, ANSWER).await;
    let s = served(instance, &agent.entry("planner", "0s"), false, None);
    approve(&s, "planner").await;
    let send = || rpc("planner", "message/send", SEND, Some(&s.token));
    let (status, body) = answered(&s.router, send()).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the approved agent is served: {body}"
    );
    assert!(agent.relayed(), "the approved agent was dialled");

    agent.go_down();
    let (status, body) = answered(&s.router, send()).await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "a card busbar could not re-verify on the call path fails the hop closed: {body}"
    );
    let doc: serde_json::Value = serde_json::from_str(&body).expect("an envelope");
    assert_eq!(doc["error"]["code"], -32004, "{body}");
    assert_eq!(
        doc["error"]["message"], "this agent is not currently serving",
        "{body}"
    );
    assert!(
        doc["error"]["data"].as_array().is_some_and(|d| d
            .iter()
            .any(|e| e["resourceType"] == surface("task_resource_type"))),
        "the refusal names its task: {body}"
    );
    assert!(!agent.relayed(), "the refused hop never reached the agent");

    let (_, state) = trust_key(&s, "planner").await;
    assert_eq!(
        state, "same",
        "the kernel's last verdict is untouched by an unreachable card"
    );

    agent.down.store(false, std::sync::atomic::Ordering::SeqCst);
    let (status, body) = answered(&s.router, send()).await;
    assert_eq!(status, StatusCode::OK, "reachable again, served: {body}");
    assert!(agent.relayed(), "dialled again");
}

/// A CARD SIGNED BY THE WRONG KEY IS REFUSED AND RECORDED AS A FAILED CONTACT (the engine's
/// `verify_tests::a_card_signed_by_the_wrong_key_is_refused_and_recorded_as_a_failed_contact`):
/// a perfectly valid signed card, not signed by the key the operator supplied out of band.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_card_signed_by_the_wrong_key_is_refused_and_recorded_as_a_failed_contact() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-wrong-key";
    let mut agent = Agent::start(200, ANSWER).await;
    let operator = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
    let section = format!(
        "planner: {{url: 'http://127.0.0.1:{}/planner', allow_private: true, reverify_ttl: \
         '0s', pin: {{mechanism: jws_issuer_key, key: '{}'}}}}",
        agent.port,
        key_info(&operator)
    );
    let s = served(instance, &section, false, None);
    let (status, view) = admin(&s, "/agents/planner/connect", "").await;
    assert_eq!(status, StatusCode::OK, "{view}");
    assert_eq!(
        view["state"], "error",
        "a card we could not authenticate must not present as an agent that is fine: {view}"
    );
    assert_eq!(
        view["failure"], "the agent card is signed, but not by the pinned issuer key",
        "{view}"
    );
    assert_eq!(view["fingerprint"], serde_json::Value::Null, "{view}");
    assert_eq!(agent.fetches(), 1, "fetched once, at the canonical path");
    let (status, refused) = admin(
        &s,
        "/agents/planner/approve",
        &format!(r#"{{"fingerprint": "{}"}}"#, agent.fingerprint()),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
    let (status, body) = answered(
        &s.router,
        rpc("planner", "message/send", SEND, Some(&s.token)),
    )
    .await;
    assert_ne!(status, StatusCode::OK, "{body}");
    assert!(
        !agent.relayed(),
        "an unauthenticated agent is never dialled"
    );
}

/// THE LEGACY WELL-KNOWN PATH IS TRIED ONLY WHEN THE CANONICAL ONE SERVED NOTHING (the engine's
/// `verify_tests::the_legacy_well_known_path_is_tried_only_when_the_canonical_one_served_nothing`):
/// a canonical path that answers nothing usable falls back to the legacy one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_legacy_well_known_path_is_tried_only_when_the_canonical_one_served_nothing() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    const LEGACY_PATH: &str = "GET /.well-known/agent.json ";
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-legacy-path";
    let issuer = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let impostor = ed25519_dalek::SigningKey::from_bytes(&[2u8; 32]);

    let split = Arc::new(AtomicBool::new(false));
    let (canonical, legacy) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let served_card = Arc::new(std::sync::Mutex::new(serde_json::Value::Null));
    let (port, _heard) = {
        let (split, canonical, legacy, served_card) = (
            Arc::clone(&split),
            Arc::clone(&canonical),
            Arc::clone(&legacy),
            Arc::clone(&served_card),
        );
        let (issuer, impostor) = (issuer.clone(), impostor.clone());
        far_end_answering(Arc::new(move |request: &str| {
            let card = served_card.lock().map(|c| c.clone()).unwrap_or_default();
            if request.starts_with(CARD_PATH) {
                canonical.fetch_add(1, Ordering::SeqCst);
                return Some(if split.load(Ordering::SeqCst) {
                    FarReply::of(200, signed(&card, &impostor).to_string())
                } else {
                    FarReply::of(404, String::new())
                });
            }
            if request.starts_with(LEGACY_PATH) {
                legacy.fetch_add(1, Ordering::SeqCst);
                return Some(FarReply::of(200, signed(&card, &issuer).to_string()));
            }
            Some(FarReply::of(200, ANSWER.to_string()))
        }))
        .await
    };
    let good = card(port, "plans the work");
    *served_card.lock().expect("the card") = good.clone();
    let section = format!(
        "planner: {{url: 'http://127.0.0.1:{port}/planner', allow_private: true, \
         reverify_ttl: '1h', pin: {{mechanism: jws_issuer_key, key: '{}'}}}}",
        key_info(&issuer)
    );
    let s = served(instance, &section, false, None);

    let (status, view) = admin(&s, "/agents/planner/connect", "").await;
    assert_eq!(status, StatusCode::OK, "{view}");
    assert_eq!(
        view["failure"],
        serde_json::Value::Null,
        "the legacy path is tolerated: {view}"
    );
    assert_eq!(
        view["fingerprint"],
        card_fingerprint(&signed(&good, &issuer)).as_str(),
        "{view}"
    );
    assert_eq!(
        canonical.load(Ordering::SeqCst),
        1,
        "canonical is tried FIRST"
    );
    assert_eq!(
        legacy.load(Ordering::SeqCst),
        1,
        "and the legacy path after it"
    );

    split.store(true, Ordering::SeqCst);
    let (status, view) = admin(&s, "/agents/planner/connect", "").await;
    assert_eq!(status, StatusCode::OK, "{view}");
    assert_eq!(view["state"], "error", "{view}");
    assert_eq!(
        view["failure"], "the agent card is signed, but not by the pinned issuer key",
        "a verification failure at the canonical path must NOT fall through to the legacy \
         one: {view}"
    );
    assert_eq!(canonical.load(Ordering::SeqCst), 2, "{view}");
    assert_eq!(
        legacy.load(Ordering::SeqCst),
        1,
        "the good card at the legacy path was never reached"
    );
}

/// A `hooks:` definition on the kernel's hook double, as an operator writes it, its `prompt:` grant
/// `prompt` and its plugin `settings`.
fn hook_def(prompt: &str, settings: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "kind": "gate",
        "module": "test-hook",
        "timeout_ms": 10_000,
        "on_error": "weighted",
        "prompt": prompt,
        "user": "ro",
        "priority": 0,
        "settings": settings,
    })
}

/// The door served with the hook `def`, named `name`, attached to the agent `planner`
/// (`agents.planner.hooks: [name]`), its egress the deployment's default stance.
fn hooked(instance: &'static str, agent: &Agent, name: &str, def: serde_json::Value) -> Served {
    served_full(
        instance,
        &agent.entry("planner", "1h"),
        busbar_kernel::config::Destinations {
            block_private_addresses: true,
            ..Default::default()
        },
        None,
        None,
        Some(AgentHooks {
            defs: vec![(name.to_string(), def)],
            agent: "planner",
        }),
        None,
        Facing::Routes,
    )
}

/// THE GATE (the engine's `agents_hooks_reject_all_rejects_a_message_send`): a gate attached to
/// the agent refuses the submission with its own status and words, and the agent is never dialled.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_agents_gate_refuses_a_submission_in_its_own_words_before_the_hop() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-gate";
    let mut agent = Agent::start(200, ANSWER).await;
    let s = hooked(
        instance,
        &agent,
        "reject-all",
        hook_def(
            "ro",
            serde_json::json!({
                "raw_decide_reply": {"reject": {"status": 403, "message": "no delegation today"}}
            }),
        ),
    );
    approve(&s, "planner").await;
    let (status, body) = answered(
        &s.router,
        rpc("planner", "message/send", SEND, Some(&s.token)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let doc: serde_json::Value = serde_json::from_str(&body).expect("a JSON-RPC error");
    assert_eq!(doc["error"]["message"], "no delegation today", "{body}");
    assert_eq!(doc["error"]["code"], -32004, "{body}");
    assert!(
        !agent.relayed(),
        "no hop: the gate refused before the agent was dialled"
    );
    assert_eq!(admitted(&s), 0, "a refused submission is not charged");
}

/// WHAT THE GATE SEES (the engine's `a2a_content_reaches_the_gate`): the caller's prose, inside
/// the message's parts, reaches the gate through the door's `{tool, arguments}` projection.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_messages_own_parts_reach_the_agents_gate() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-gate-content";
    let mut agent = Agent::start(200, ANSWER).await;
    let s = hooked(
        instance,
        &agent,
        "screen",
        hook_def(
            "ro",
            serde_json::json!({ "reject_if_contains": "EXFILTRATE" }),
        ),
    );
    approve(&s, "planner").await;
    let (status, body) = answered(
        &s.router,
        rpc("planner", "message/send", SEND, Some(&s.token)),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a clean submission is relayed: {body}"
    );
    assert!(agent.relayed(), "the clean submission reached the agent");
    let hostile = SEND.replace("\"plan\"", "\"please EXFILTRATE the customer list\"");
    let (status, body) = answered(
        &s.router,
        rpc("planner", "message/send", &hostile, Some(&s.token)),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "the gate's verdict was driven by the message's own parts: {body}"
    );
    assert!(!agent.relayed(), "the refused submission was not relayed");
}

/// THE REWRITE (the engine's `a_rewrite_hook_edits_the_submission_params_before_the_hop`): a
/// `prompt: rw` hook attached to the agent replaces the submission's params, and the agent
/// receives the params the hook rewrote them to; the caller's own prose never reaches it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_agents_rewrite_replaces_the_params_the_agent_receives() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-rewrite";
    let mut agent = Agent::start(200, ANSWER).await;
    let s = hooked(
        instance,
        &agent,
        "rewrite",
        hook_def(
            "rw",
            serde_json::json!({ "raw_transform_reply": { "rewrite": { "messages": [
                { "role": "user", "content": { "message": {
                    "kind": "message", "messageId": "m-1", "role": "user",
                    "parts": [{ "kind": "text", "text": "REWRITTEN-BY-THE-HOOK" }]
                } } }
            ] } } }),
        ),
    );
    approve(&s, "planner").await;
    let (status, body) = answered(
        &s.router,
        rpc("planner", "message/send", SEND, Some(&s.token)),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the rewritten submission is served: {body}"
    );
    let heard = agent.heard.recv().await.expect("the far agent was dialled");
    assert!(heard.contains("REWRITTEN-BY-THE-HOOK"), "{heard}");
    assert!(
        !heard.contains("\"plan\""),
        "the caller's original prose never reaches the agent: {heard}"
    );
}

/// A `GET` of `path` on the data router, bearing `token` or none.
fn get(path: &str, token: Option<&str>) -> axum::http::Request<axum::body::Body> {
    let mut req = axum::http::Request::builder().method("GET").uri(path);
    if let Some(token) = token {
        req = req.header("authorization", format!("Bearer {token}"));
    }
    req.body(axum::body::Body::empty()).expect("a request")
}

/// The door declares that a breaker cell refuses on a trip, not below the trip threshold.
#[test]
fn the_agent_door_states_a_cell_refuses_on_a_trip_and_nothing_less() {
    let door = door();
    let row = LinkedRow::of(door).expect("the door states its Statement");
    let name = busbar_contract::abi::mechanism::rendering::read(&row.statement)
        .expect("its Statement reads")
        .name;
    let stated = crate::root::linked::door_breaker(&crate::LINKED, None, &name)
        .expect("its declares section reads");
    assert_eq!(stated.map(|b| b.bench_below_trip_threshold), Some(false));
}

/// BUSBAR'S OWN CARD at the well-known path: unauthenticated, cacheable for an hour, describing
/// busbar (every binding it serves, no fronted agent enumerated) and signed with busbar's key.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn busbars_own_card_is_served_at_the_well_known_path_signed_and_naming_no_agent() {
    use tower::ServiceExt as _;
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-own-card";
    let agent = Agent::start(200, ANSWER).await;
    let s = served(instance, &agent.entry("planner", "1h"), false, None);
    let response = s
        .router
        .clone()
        .oneshot(get("/.well-known/agent-card.json", None))
        .await
        .expect("the router answers");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "public, max-age=3600");
    assert_eq!(
        response.headers()["content-type"],
        "application/json; charset=utf-8"
    );
    let body = axum::body::to_bytes(response.into_body(), 1 << 16)
        .await
        .expect("the body");
    let card: serde_json::Value = serde_json::from_slice(&body).expect("a card");
    assert_eq!(card["name"], "busbar");
    assert_eq!(card["skills"], serde_json::json!([]));
    assert_eq!(
        card["supportedInterfaces"][0],
        serde_json::json!({
            "url": format!("https://gw.example{}", mount()),
            "protocolBinding": "JSONRPC",
            "protocolVersion": "1.0",
        })
    );
    let protected = card["signatures"][0]["protected"]
        .as_str()
        .expect("signed with busbar's key");
    assert!(!protected.is_empty());
    assert!(
        !String::from_utf8_lossy(&body).contains("planner"),
        "no agent is enumerated"
    );
}

/// A FRONTED AGENT'S CARD behind the caller's credential: refused without one, and once the
/// agent is approved, its card with every URL busbar's and busbar's own scheme and signature.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_fronted_agents_card_is_served_rewritten_through_busbar_behind_its_grant() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-agent-card";
    let agent = Agent::start(200, ANSWER).await;
    let s = served(instance, &agent.entry("planner", "1h"), false, None);
    let (status, _) = answered(&s.router, get(&format!("{}/agents/planner", mount()), None)).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "the card needs a credential"
    );
    approve(&s, "planner").await;
    let (status, body) = answered(
        &s.router,
        get(&format!("{}/agents/planner", mount()), Some(&s.token)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let card: serde_json::Value = serde_json::from_str(&body).expect("a card");
    assert!(
        !body.contains(&format!("127.0.0.1:{}", agent.port)),
        "the backend authority is never published: {body}"
    );

    assert_eq!(
        card["securityRequirements"],
        serde_json::json!([{ "schemes": { "busbarA2aInbound": { "list": [] } } }])
    );
    assert_eq!(
        card["securitySchemes"]["busbarA2aInbound"]["httpAuthSecurityScheme"]["scheme"],
        "Bearer"
    );
    assert_eq!(
        card["capabilities"],
        serde_json::json!({}),
        "the agent's card states no capability, and busbar promises none on its behalf"
    );
    assert!(card["signatures"][0]["protected"].is_string(), "{body}");
}

/// A CARD READ IS NOT SCREENED: with a gate attached to the agent that refuses every
/// submission, the agent's card is still served to a granted caller (1.5.5 answered a card read
/// with no hook in the way), while a submission to the same agent is refused by the gate.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_gated_agents_card_is_still_served_and_its_submission_refused() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-gated-card";
    let mut agent = Agent::start(200, ANSWER).await;
    let s = hooked(
        instance,
        &agent,
        "reject-all",
        hook_def(
            "ro",
            serde_json::json!({
                "raw_decide_reply": {"reject": {"status": 403, "message": "no delegation today"}}
            }),
        ),
    );
    approve(&s, "planner").await;
    let (status, body) = answered(
        &s.router,
        get(&format!("{}/agents/planner", mount()), Some(&s.token)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the card is served: {body}");
    let card: serde_json::Value = serde_json::from_str(&body).expect("a card");
    assert!(card["name"].is_string(), "{body}");
    let (status, body) = answered(
        &s.router,
        rpc("planner", "message/send", SEND, Some(&s.token)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(!agent.relayed(), "the refused submission was not relayed");
}

/// BUSBAR'S EXTENDED CARD on the plane's own endpoint: one skill per agent the caller's own
/// catalogue holds, answered by busbar, never relayed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_extended_card_on_the_planes_endpoint_names_the_callers_agents() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-extended-card";
    let mut agent = Agent::start(200, ANSWER).await;
    let s = served(instance, &agent.entry("planner", "1h"), false, None);
    approve(&s, "planner").await;
    let (status, body) = answered(
        &s.router,
        rpc("", "GetExtendedAgentCard", "{}", Some(&s.token)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let doc: serde_json::Value = serde_json::from_str(&body).expect("an answer");
    assert_eq!(doc["id"], 1);
    let skills = doc["result"]["skills"].as_array().expect("skills");
    assert_eq!(skills.len(), 1, "{body}");
    assert_eq!(skills[0]["id"], "planner");
    assert!(
        !agent.relayed(),
        "the extended card is busbar's, never relayed"
    );
}
/// A unit addressed to an agent nothing registered is a `404`, never dialled and charging
/// nothing; it does not read as an out-of-scope one (that is the grant's refusal, in
/// `an_agent_unit_outside_the_callers_grant_is_refused_before_it_dials`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_agent_unit_to_an_unregistered_agent_is_a_404() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-unregistered";
    let (port, mut heard) = far_agent().await;
    let s = served(instance, &agents(port, false), false, None);
    let (status, body) = answered(
        &s.router,
        rpc("nonexistent", "message/send", SEND, Some(&s.token)),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert!(
        !body.contains("scope_denied"),
        "an unregistered agent is not an out-of-scope one: {body}"
    );
    assert!(heard.try_recv().is_err(), "nothing was dialled");
    assert_eq!(admitted(&s), 0, "nothing charged");
}

/// AN UNKNOWN AGENT HAS NO SCOPE TO BE GRANTED ON: a key whose grant reaches no agent at all,
/// addressing one nothing registered, is told the agent does not exist (`404`, `-32004`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_agent_unit_from_a_restricted_key_to_an_unregistered_agent_is_a_404() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-unregistered-restricted";
    let (port, mut heard) = far_agent().await;
    let s = served(instance, &agents(port, false), false, Some(Vec::new()));
    let (status, body) = answered(
        &s.router,
        rpc("nonexistent", "message/send", SEND, Some(&s.token)),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "absent before its grant: {body}"
    );
    let doc: serde_json::Value = serde_json::from_str(&body).expect("an envelope");
    assert_eq!(doc["error"]["code"], -32004, "{body}");
    assert_eq!(
        doc["error"]["message"], "no fronted agent `nonexistent`",
        "{body}"
    );
    assert_eq!(doc["id"], serde_json::Value::Null, "{body}");
    assert!(heard.try_recv().is_err(), "nothing was dialled");
    assert_eq!(admitted(&s), 0, "nothing charged");
}

/// A tripped agent refuses a fresh submission with `503` and a `Retry-After` of at least one
/// second, on the JSON-RPC line and on the HTTP+JSON line, and never dials.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tripped_agent_refuses_a_fresh_submission_with_503_and_retry_after() {
    use tower::ServiceExt as _;
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-breaker-503";
    let mut agent = Agent::start(503, r#"{"error":"down"}"#).await;
    let s = served(instance, &agent.entry("planner", "1h"), false, None);
    approve(&s, "planner").await;
    let mut tripped = false;
    for _ in 0..32 {
        let (_, body) = answered(
            &s.router,
            rpc("planner", "message/send", SEND, Some(&s.token)),
        )
        .await;
        if body.contains("breaker_open") {
            tripped = true;
            break;
        }
    }
    assert!(tripped, "the breaker opened within 32 failing calls");
    agent.relayed();
    let rest = axum::http::Request::builder()
        .method("POST")
        .uri(format!("{}/message:send", mount()))
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", s.token))
        .body(axum::body::Body::from(format!(
            r#"{{"message":{}}}"#,
            &SEND[11..SEND.len() - 1]
        )))
        .expect("a request");
    for (line, req) in [
        (
            "JSON-RPC",
            rpc("planner", "message/send", SEND, Some(&s.token)),
        ),
        ("HTTP+JSON", rest),
    ] {
        let response = s.router.clone().oneshot(req).await.expect("answers");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE, "{line}");
        let wait: u64 = response
            .headers()
            .get("retry-after")
            .unwrap_or_else(|| panic!("{line}: no Retry-After"))
            .to_str()
            .expect("text")
            .parse()
            .expect("seconds");
        assert!(wait >= 1, "{line}: Retry-After {wait}");
        let body = axum::body::to_bytes(response.into_body(), 1 << 16)
            .await
            .expect("body");
        let body = String::from_utf8_lossy(&body);
        assert!(body.contains("breaker_open"), "{line}: {body}");
        assert!(
            body.contains("agent `planner`"),
            "{line}: the refusal names the agent the unit was routed to: {body}"
        );
    }
    assert!(!agent.relayed(), "a tripped agent is never dialled");
}

/// The id of the task a breaker refusal names, read where a conformant client reads it: the
/// `ResourceInfo` of type `a2a.busbar/task` in `error.data` (the JSON-RPC line) or in the
/// AIP-193 document's `error.details` (the HTTP+JSON line).
fn refused_task_id(body: &str) -> String {
    let doc: serde_json::Value = serde_json::from_str(body).expect("a refusal");
    doc.pointer("/error/data")
        .or_else(|| doc.pointer("/error/details"))
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .find(|e| e["resourceType"] == surface("task_resource_type"))
        .and_then(|e| e["resourceName"].as_str())
        .unwrap_or_else(|| panic!("the refusal must name the task: {body}"))
        .to_string()
}

/// THE `rejected` HALF of predev's `breaker_fastfail_tests.rs::battery` (lines 329-338), on one
/// binding: trip the agent, then a fresh submission is refused `503` and its task is stored
/// `rejected`.
async fn rejected_battery(
    s: &Served,
    agent: &mut dyn FnMut() -> bool,
    (method, params): (&str, &str),
    line: &str,
    rest: bool,
) {
    use tower::ServiceExt as _;
    let mut tripped = false;
    for _ in 0..32 {
        let (_, body) = answered(&s.router, rpc("planner", method, params, Some(&s.token))).await;
        if body.contains("breaker_open") {
            tripped = true;
            break;
        }
    }
    assert!(
        tripped,
        "[{line}] the breaker opened within 32 failing calls"
    );
    agent();
    let req = if rest {
        axum::http::Request::builder()
            .method("POST")
            .uri(format!("{}/message:send", mount()))
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", s.token))
            .body(axum::body::Body::from(format!(
                r#"{{"message":{}}}"#,
                &SEND[11..SEND.len() - 1]
            )))
            .expect("a request")
    } else {
        rpc("planner", method, params, Some(&s.token))
    };
    let response = s.router.clone().oneshot(req).await.expect("answers");
    assert_eq!(
        response.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "[{line}]"
    );
    let wait: u64 = response
        .headers()
        .get("retry-after")
        .unwrap_or_else(|| panic!("[{line}] the refusal carries Retry-After"))
        .to_str()
        .expect("text")
        .parse()
        .expect("seconds");
    assert!(wait >= 1, "[{line}] Retry-After {wait}");
    let body = axum::body::to_bytes(response.into_body(), 1 << 16)
        .await
        .expect("body");
    let body = String::from_utf8_lossy(&body).into_owned();
    assert!(body.contains("breaker_open"), "[{line}] {body}");
    assert!(!agent(), "[{line}] a tripped agent is never dialled");
    let task = refused_task_id(&body);

    let (status, listed) =
        answered(&s.router, rpc("planner", "ListTasks", "{}", Some(&s.token))).await;
    assert_eq!(status, StatusCode::OK, "[{line}] {listed}");
    let listed: serde_json::Value = serde_json::from_str(&listed).expect("a listing");
    let row = listed["result"]["tasks"]
        .as_array()
        .and_then(|tasks| tasks.iter().find(|t| t["id"] == task.as_str()))
        .unwrap_or_else(|| panic!("[{line}] the named task must resolve in the store: {listed}"));
    let state = row["status"]["state"]
        .as_str()
        .unwrap_or_default()
        .to_ascii_lowercase();
    assert!(
        state.contains("rejected"),
        "[{line}] a breaker refusal is `rejected`, never `failed`: {row}"
    );

    let get = format!(r#"{{"id":"{task}"}}"#);
    let response = {
        use tower::ServiceExt as _;
        s.router
            .clone()
            .oneshot(rpc("planner", "tasks/get", &get, Some(&s.token)))
            .await
            .expect("answers")
    };
    assert_eq!(
        response.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "[{line}]"
    );
    assert!(
        response.headers().get("retry-after").is_some(),
        "[{line}] the relayed read carries Retry-After"
    );
    let refused = axum::body::to_bytes(response.into_body(), 1 << 16)
        .await
        .expect("body");
    let refused = String::from_utf8_lossy(&refused);
    assert!(
        refused.contains("breaker_open") && refused.contains("agent `planner`"),
        "[{line}] tasks/get is refused in the breaker's words: {refused}"
    );
    assert!(!agent(), "[{line}] the read never dialled the agent");
}

/// Ported from busbar-a2a a2a/tests/breaker_fastfail_tests.rs::a_tripped_agent_rejects_fresh_submissions_on_the_jsonrpc_binding
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tripped_agent_rejects_fresh_submissions_on_the_jsonrpc_binding() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-breaker-rejected-jsonrpc";
    let mut agent = Agent::start(401, r#"{"error":"denied"}"#).await;
    let s = served(instance, &agent.entry("planner", "1h"), false, None);
    approve(&s, "planner").await;
    rejected_battery(
        &s,
        &mut || agent.relayed(),
        ("message/send", SEND),
        "jsonrpc",
        false,
    )
    .await;
}

/// Ported from busbar-a2a a2a/tests/breaker_fastfail_tests.rs::a_tripped_agent_rejects_fresh_submissions_on_the_httpjson_binding
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tripped_agent_rejects_fresh_submissions_on_the_httpjson_binding() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-breaker-rejected-httpjson";
    let mut agent = Agent::start(401, r#"{"error":"denied"}"#).await;
    let s = served(instance, &agent.entry("planner", "1h"), false, None);
    approve(&s, "planner").await;
    rejected_battery(
        &s,
        &mut || agent.relayed(),
        ("message/send", SEND),
        "httpjson",
        true,
    )
    .await;
}

/// Ported from busbar-a2a a2a/tests/breaker_fastfail_tests.rs::a_tripped_agent_rejects_fresh_submissions_on_the_grpc_binding
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tripped_agent_rejects_fresh_submissions_on_the_grpc_binding() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-breaker-rejected-grpc";
    let mut agent = GrpcAgent::serving(Vec::new(), "16", 200, None).await;
    let s = served(instance, &agent.entry("planner"), false, None);
    approve(&s, "planner").await;
    let params = r#"{"message":{"messageId":"m-1","role":"ROLE_USER","parts":[{"text":"PLAN THE MIGRATION"}]}}"#;
    rejected_battery(
        &s,
        &mut || {
            let mut heard = false;
            while agent.heard.try_recv().is_ok() {
                heard = true;
            }
            heard
        },
        ("SendMessage", params),
        "grpc",
        false,
    )
    .await;
}

/// THE EXTENDED CARD IS METERED: busbar answers it out of its own state, and it is still one
/// admitted request on the presenting key, with no token accrual (a verb answered locally
/// selects no upstream and relays no frame, so no per-request token fee can land on it).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_extended_card_is_metered_as_one_request_and_no_tokens() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-extended-card-metered";
    let mut agent = Agent::start(200, ANSWER).await;
    let s = served(instance, &agent.entry("planner", "1h"), false, None);
    approve(&s, "planner").await;
    let history = busbar_kernel::host_records_async::AsyncHistory::authorized(
        s.gov
            .core_store_handle()
            .expect("admitted native persistence"),
        busbar_kernel::audit::auditlog::PERSISTENCE_OWNER,
        [busbar_kernel::host_records_async::HistoryCollection {
            kind: busbar_kernel::store::plane_view::KIND_AUDIT,
            mode: busbar_kernel::host_records_async::HistoryMode::Append,
            retention: busbar_contract::records::Retention::Age,
            parent: None,
        }],
    )
    .expect("the host's declared audit collection");
    let durable_admin = history
        .list(
            busbar_kernel::store::plane_view::KIND_AUDIT,
            &busbar_contract::records::PlaneSelector::Parent("admin".into()),
        )
        .await
        .expect("the actual Store reads its durable admin journal");
    let durable_admin: BTreeMap<_, _> = durable_admin
        .iter()
        .map(|record| {
            let row: busbar_kernel::audit::journal::NeutralBody =
                busbar_kernel::store::plane_view::decode(&record.body)
                    .expect("a durable admin journal row");
            (row.seq, row.hash)
        })
        .collect();
    let approvals = busbar_kernel::audit::auditlog::AUDIT_LOG.list_filtered(
        0,
        1000,
        Some("a2a_agent.approve"),
        None,
    );
    assert!(
        approvals.iter().any(|row| row.resource.contains("planner")
            && durable_admin.get(&row.seq) == Some(&row.hash)),
        "the planner approval is durable in this Store, rather than queued: {approvals:?}"
    );
    assert_eq!(admitted(&s), 0, "nothing billed before the call");
    let (status, body) = answered(
        &s.router,
        rpc("", "GetExtendedAgentCard", "{}", Some(&s.token)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the card is still answered: {body}");
    let doc: serde_json::Value = serde_json::from_str(&body).expect("an answer");
    assert!(
        doc.get("result").is_some(),
        "the card verb must still return a card, not merely a bill: {body}"
    );
    assert_eq!(doc["id"], 1, "the card answers this request");
    let skills = doc["result"]["skills"]
        .as_array()
        .expect("the card's skills");
    assert_eq!(skills.len(), 1, "the caller's actual catalogue: {body}");
    assert_eq!(skills[0]["id"], "planner", "the caller's approved agent");
    let usage = futures::executor::block_on(s.gov.usage_for_async(
        &s.app.cost,
        &s.key.id,
        busbar_kernel::store::now(),
    ))
    .expect("a read")
    .expect("the key exists");
    assert_eq!(usage.requests, 1, "one call, one request accrual");
    assert_eq!(usage.tokens, 0, "a locally answered verb accrues no tokens");

    let lane_counts: BTreeMap<_, _> = s
        .gov
        .bucket_model_tokens_async(
            &s.key.id,
            busbar_kernel::governance::WINDOW_TOTAL,
            busbar_kernel::store::now(),
        )
        .await
        .expect("read native metering lanes")
        .into_iter()
        .collect();
    assert_eq!(
        lane_counts,
        BTreeMap::from([
            (
                busbar_kernel::cost::plane_fee_lane(surface("plane_key")),
                BTreeMap::new()
            ),
            (surface("section").to_string(), BTreeMap::new()),
        ]),
        "the plane fee and pool lanes carry no counts for a locally answered card"
    );
    let member = format!("{}:", surface("resource_kind"));
    assert!(
        lane_counts.keys().all(|lane| !lane.contains(&member)),
        "the card is on no member line: {lane_counts:?}"
    );
    let billed = Billed::of(&s);
    assert_eq!(
        (billed.requests, billed.fees, billed.bytes, billed.spend),
        (1, 0, 0, 0),
        "one local admission charges no upstream fee, bytes, or spend"
    );
    let audit = caller_counts(&s);
    assert_eq!(
        audit.len(),
        1,
        "one admitted card seals one caller record: {audit:?}"
    );
    assert!(audit[0].classes.is_empty(), "no upstream usage: {audit:?}");
    assert_eq!(audit[0].fee_count, 0, "no upstream fee: {audit:?}");
    assert!(
        !agent.relayed(),
        "the extended card is busbar's, never relayed"
    );
}

use busbar_contract::records::{ScopeRef, VirtualKey};

/// The `message/stream` params the streamed cells send.
const STREAM: &str = r#"{"message":{"kind":"message","messageId":"m-s","role":"user","contextId":"ctx-scan","parts":[{"kind":"text","text":"STREAM THE PLAN"}]}}"#;

/// A far agent's answer in events: one frame carrying its finished task.
const STREAMED: &str = "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"kind\":\"task\",\"id\":\"B1\",\"contextId\":\"BC\",\"status\":{\"state\":\"completed\"}}}\n\n";

/// The media type an answer in events is served as.
const EVENTS: &str = "text/event-stream";

/// The credential busbar itself presents to an agent (its `upstream_credential:`), as its
/// secret file holds it.
const LEASED: &str = "leased-outbound-cred-BUSBAR-PRESENTS-THIS-7f3a";

/// The `upstream_credential:` pair presenting [`LEASED`] as a bearer: its secret a file under
/// the system temp directory, written here, one per instance.
struct LeaseFile(std::path::PathBuf);
impl Drop for LeaseFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
fn leased(instance: &str) -> (LeaseFile, String) {
    let path = std::env::temp_dir().join(format!("{instance}-{}.lease", std::process::id()));
    std::fs::write(&path, LEASED).expect("the lease's secret file");
    let config = format!(
        "upstream_credential: {{secret: {{file: '{}'}}, lease_ttl_ms: 60000}}",
        path.display()
    );
    (LeaseFile(path), config)
}

/// Encodings a secret could plausibly be smuggled in. A scan that only looked for the
/// plaintext would be defeated by `base64` and would say so with a green tick.
fn encodings(secret: &str) -> Vec<(&'static str, Vec<u8>)> {
    use base64::Engine as _;
    use sha2::Digest as _;
    vec![
        ("plain", secret.as_bytes().to_vec()),
        (
            "base64",
            base64::engine::general_purpose::STANDARD
                .encode(secret)
                .into_bytes(),
        ),
        (
            "base64url-nopad",
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(secret)
                .into_bytes(),
        ),
        ("hex", hex::encode(secret).into_bytes()),
        // "we only sent a hash of it" is still sending a value derived from a credential to a
        // party that has no business holding one.
        (
            "sha256-hex",
            hex::encode(sha2::Sha256::digest(secret.as_bytes())).into_bytes(),
        ),
    ]
}

/// Whether `needle` occurs in `haystack`.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// Everything the far agent was sent since it was last asked, end to end.
fn wire(agent: &mut Agent) -> Vec<u8> {
    let mut all = Vec::new();
    while let Ok(request) = agent.heard.try_recv() {
        all.extend_from_slice(request.as_bytes());
    }
    all
}

/// [`rpc`] presenting `value` in the head field `field` as its credential, and no bearer.
fn rpc_presenting(
    agent: &str,
    method: &str,
    params: &str,
    field: &'static str,
    value: &str,
) -> axum::http::Request<axum::body::Body> {
    let mut req = rpc(agent, method, params, None);
    req.headers_mut().insert(
        field,
        axum::http::HeaderValue::from_str(value).expect("a head value"),
    );
    req
}

/// Present a genuine Store-minted caller binding to this fixture's advertised resource.
/// Normal root composition publishes the audience for every configured A2A front, so positive
/// ingress calls need that audience as well as the durable key's exact minted generation.
fn caller_resource_token(token: &str) -> String {
    let signer = TokenSigner::from_secret_bytes(&[9u8; 32], DEFAULT_KID);
    let claims = busbar_kernel::governance::signing::TokenVerifier::single(
        signer.kid(),
        signer.verifying_key(),
    )
    .verify(token, 1_700_000_000, None)
    .expect("the actual Store-minted caller binding verifies before resource binding");
    signer.mint_for_audience(
        &claims.sub,
        claims.exp,
        claims.generation.as_deref(),
        &format!("https://gw.example{}", mount()),
        None,
    )
}

/// The cell's own token's binding generation, as the book minted it.
fn generation_of(s: &Served) -> Option<String> {
    let signer = TokenSigner::from_secret_bytes(&[9u8; 32], DEFAULT_KID);
    busbar_kernel::governance::signing::TokenVerifier::single(signer.kid(), signer.verifying_key())
        .verify(
            &s.token,
            1_700_000_000,
            Some(&format!("https://gw.example{}", mount())),
        )
        .expect("the cell's own token verifies")
        .generation
}

/// The cell's own key's token bound to the resource `audience` (RFC 8707), as the book's
/// signing key mints one.
fn bound_to(s: &Served, audience: &str) -> String {
    TokenSigner::from_secret_bytes(&[9u8; 32], DEFAULT_KID).mint_for_audience(
        &s.key.id,
        4_000_000_000,
        generation_of(s).as_deref(),
        audience,
        None,
    )
}

/// The grant naming agent `agent`.
fn agent_scope(agent: &str) -> ScopeRef {
    ScopeRef {
        kind: surface("scope_kind").to_string(),
        value: agent.to_string(),
    }
}

/// Another caller on `s`'s book: a key minted beside the cell's own, its grant then written as
/// exactly `scopes` (`None` = every scope); its row and its token.
fn another_caller(s: &Served, name: &str, scopes: Option<Vec<ScopeRef>>) -> (VirtualKey, String) {
    let (key, token) = futures::executor::block_on(s.gov.mint_signed_async(
        NewKeySpec {
            name: name.to_string(),
            allowed_pools: None,
            ..Default::default()
        },
        4_000_000_000,
        1_700_000_000,
    ))
    .expect("mint");
    let mut row = futures::executor::block_on(
        s.gov
            .core_store()
            .expect("native identity owner")
            .identity()
            .get_key(&key.id),
    )
    .expect("a read")
    .expect("the key's row");
    row.allowed_scopes = scopes;
    futures::executor::block_on(
        s.gov
            .core_store()
            .expect("native identity owner")
            .identity()
            .put_key(&row),
    )
    .expect("the grant is written");
    futures::executor::block_on(s.gov.refresh_async()).expect("the book reloads");
    (
        row,
        caller_resource_token(token.expose(&busbar_kernel::seal::lend())),
    )
}

/// The agents busbar's extended card names for the caller presenting `token`: its status, and
/// each skill's id, sorted.
async fn agents_seen(s: &Served, token: &str) -> (StatusCode, Vec<String>) {
    let (status, body) = answered(
        &s.router,
        rpc("", "GetExtendedAgentCard", "{}", Some(token)),
    )
    .await;
    let doc: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
    let mut ids: Vec<String> = doc["result"]["skills"]
        .as_array()
        .map(|skills| {
            skills
                .iter()
                .filter_map(|s| s["id"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    ids.sort();
    (status, ids)
}

/// The `agents:` section registering `planner` and `scout` on `agent`, both pinned by its key.
fn two_agents(agent: &Agent) -> String {
    format!(
        "{}\n{}",
        agent.entry("planner", "1h"),
        agent.entry("scout", "1h")
    )
}

/// Ported from busbar-a2a ingress_tests.rs::no_agents_configured_means_no_route_in_the_table_at_all.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_deployment_writing_no_agents_section_mounts_no_agent_route_at_all() {
    let _one = PUBLISHING.lock().await;
    let mut agent = Agent::start(200, ANSWER).await;
    let section = agent.entry("planner", "1h");
    let metadata = format!("/.well-known/oauth-protected-resource{}", mount());
    let card = "/.well-known/agent-card.json";
    let agent_routes = |routes: &[String]| -> Vec<String> {
        routes
            .iter()
            .filter(|p| p.starts_with(mount()) || **p == metadata || p.as_str() == card)
            .cloned()
            .collect()
    };

    let configured = "serve-agent-door-configured";
    let s = served_facing(configured, &section, Facing::Routes);
    let mounted = agent_routes(&s.routes);
    assert!(
        mounted.contains(&metadata)
            && mounted.iter().any(|p| p == card)
            && mounted
                .iter()
                .any(|p| p.starts_with(&format!("{}/agents", mount()))),
        "the control: a written section mounts the door's routes: {:?}",
        s.routes
    );

    let absent = "serve-agent-door-unconfigured";
    let s = served_facing(absent, &section, Facing::Unconfigured);
    assert!(
        agent_routes(&s.routes).is_empty(),
        "a deployment with no `agents:` mounted an agent route: {:?}",
        s.routes
    );
    let (status, body) = answered(
        &s.router,
        rpc("planner", "message/send", SEND, Some(&s.token)),
    )
    .await;
    assert_ne!(status, StatusCode::OK, "nothing serves it: {body}");
    let (status, body) = answered(&s.router, get(card, None)).await;
    assert_ne!(status, StatusCode::OK, "no card is served: {body}");
    assert!(!agent.relayed(), "no agent was dialled");
}

/// Ported from busbar-a2a plane_tests.rs::a_section_carrying_only_the_reserved_keys_is_still_no_plane.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_section_carrying_only_the_reserved_keys_is_still_no_plane() {
    let _one = PUBLISHING.lock().await;
    let mut agent = Agent::start(200, ANSWER).await;
    let metadata = format!("/.well-known/oauth-protected-resource{}", mount());
    let card = "/.well-known/agent-card.json";
    /// What the door's paths answer on `s`, each asked by its keyed caller where it is keyed.
    async fn asked(s: &Served, metadata: &str, card: &str) -> Vec<(StatusCode, String)> {
        let token = Some(s.token.as_str());
        let mut answers = Vec::new();
        for req in [
            get(card, None),
            get(metadata, None),
            get(&format!("{}/agents/planner", mount()), token),
            rpc("planner", "message/send", SEND, token),
            rpc("", "message/send", SEND, token),
            rpc("", "GetExtendedAgentCard", "{}", token),
        ] {
            answers.push(answered(&s.router, req).await);
        }
        answers
    }

    let absent = "serve-agent-door-no-section";
    let unconfigured = served_facing(absent, &agent.entry("planner", "1h"), Facing::Unconfigured);
    let baseline = asked(&unconfigured, &metadata, card).await;

    let reserved = "serve-agent-door-reserved-keys-only";
    let s = served_facing(
        reserved,
        "hooks: []\nupstream_credentials: own",
        Facing::Routes,
    );
    let mounted: Vec<&String> = s
        .routes
        .iter()
        .filter(|p| p.starts_with(mount()) || **p == metadata || p.as_str() == card)
        .collect();
    assert!(
        mounted.is_empty(),
        "a section carrying only the reserved keys mounted an agent route: {:?}",
        s.routes
    );
    let answers = asked(&s, &metadata, card).await;
    for (answer, expected) in answers.iter().zip(&baseline) {
        assert_ne!(answer.0, StatusCode::OK, "nothing serves it: {answer:?}");
        assert_eq!(
            answer, expected,
            "it answers as a deployment with no `agents:` section does"
        );
    }
    assert!(!agent.relayed(), "no agent was dialled");
}

/// Ported from busbar-a2a ingress_tests.rs::an_anonymous_caller_is_refused_and_told_where_to_get_a_token.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_anonymous_caller_is_refused_and_told_where_to_get_a_token() {
    use tower::ServiceExt as _;
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-anonymous";
    let mut agent = Agent::start(200, ANSWER).await;
    let s = served_facing(instance, &agent.entry("planner", "1h"), Facing::Admitted);
    let response = s
        .router
        .clone()
        .oneshot(rpc("planner", "message/send", SEND, None))
        .await
        .expect("the router answers");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let challenge = response
        .headers()
        .get("www-authenticate")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let document = format!(
        "https://gw.example/.well-known/oauth-protected-resource{}",
        mount()
    );
    assert!(
        challenge.contains(&document),
        "the challenge does not name the door's metadata document: {challenge:?}"
    );
    assert!(!agent.relayed(), "a refused caller dials nothing");
}

/// Ported from busbar-a2a ingress_tests.rs::the_metadata_document_advertises_the_audience_the_verifier_demands.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_metadata_document_advertises_the_audience_the_verifier_demands() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-metadata";
    let agent = Agent::start(200, ANSWER).await;
    let s = served_facing(instance, &agent.entry("planner", "1h"), Facing::Admitted);
    approve(&s, "planner").await;
    let expected = s
        .app
        .planes
        .admission_for(&format!("{}/agents/planner", mount()))
        .expect("the door's claim is audience-bound")
        .audience
        .clone();

    let (status, body) = answered(
        &s.router,
        get(
            &format!("/.well-known/oauth-protected-resource{}", mount()),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let doc: serde_json::Value = serde_json::from_str(&body).expect("the document");
    assert_eq!(
        doc["resource"],
        expected.as_str(),
        "the document advertises an audience the verifier does not demand"
    );
    let token = bound_to(&s, doc["resource"].as_str().expect("its resource"));
    let (status, body) =
        answered(&s.router, rpc("planner", "tasks/list", "{}", Some(&token))).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a token bound to the advertised resource is admitted: {body}"
    );
}

/// Ported from busbar-a2a inbound_tests.rs::a_credential_of_another_kind_is_refused_with_401_and_never_names_a_backend.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_credential_of_another_kind_is_refused_with_401_and_never_names_a_backend() {
    use base64::Engine as _;
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-other-kind";
    let mut agent = Agent::start(200, ANSWER).await;
    let s = served(instance, &agent.entry("planner", "1h"), false, None);
    approve(&s, "planner").await;
    let elsewhere = bound_to(&s, "https://other.example/resource");
    let basic = base64::engine::general_purpose::STANDARD.encode("delegator:secret");
    for (what, field, value) in [
        (
            "the operator credential as a bearer",
            "authorization",
            format!("Bearer {ADMIN_TOKEN}"),
        ),
        (
            "the operator credential on its own carrier",
            "x-admin-token",
            ADMIN_TOKEN.to_string(),
        ),
        (
            "a bearer busbar never minted",
            "authorization",
            "Bearer sk-not-a-busbar-key".to_string(),
        ),
        (
            "a basic credential",
            "authorization",
            format!("Basic {basic}"),
        ),
        (
            "a key bound to another resource",
            "authorization",
            format!("Bearer {elsewhere}"),
        ),
    ] {
        let (status, body) = answered(
            &s.router,
            rpc_presenting("planner", "message/send", SEND, field, &value),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{what}: {body}");
        assert!(
            !body.contains("127.0.0.1"),
            "{what}: the refusal named the backend: {body}"
        );
        assert!(!agent.relayed(), "{what}: no agent was dialled");
    }
    assert_eq!(admitted(&s), 0, "nothing was charged");
}

/// Ported from busbar-a2a relay_stream_tests.rs::the_callers_busbar_key_is_absent_from_the_stream_wire_too.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_callers_busbar_key_is_absent_from_the_stream_wire_too() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-stream-scan";
    let mut agent = Agent::start_with(
        200,
        STREAMED,
        vec![("content-type", EVENTS.to_string())],
        None,
    )
    .await;
    agent.streams();
    let (_lease, credential) = leased(instance);
    let section = agent.entry_with("planner", "1h", &credential);
    let s = served(instance, &section, false, None);
    approve(&s, "planner").await;
    let (status, body) = answered(
        &s.router,
        rpc("planner", "message/stream", STREAM, Some(&s.token)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "streamed through the door: {body}");
    assert!(
        body.contains("completed"),
        "the agent's event, relayed: {body}"
    );

    let wire = wire(&mut agent);
    assert!(wire.len() > 100, "the scan has nothing to scan");
    assert!(
        contains(&wire, b"STREAM THE PLAN"),
        "the streamed hop carried the caller's message"
    );
    for (encoding, bytes) in &encodings(&s.token) {
        assert!(
            !contains(&wire, bytes),
            "the caller's busbar key reached the agent on the STREAM path, as {encoding}"
        );
    }
    assert!(
        contains(&wire, LEASED.as_bytes()),
        "the control: the scanner must find the credential that IS legitimately forwarded"
    );
}

/// Ported from busbar-a2a relay_stream_tests.rs::a_stream_hop_that_fails_before_its_first_event_is_a_busbar_attributed_error.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stream_hop_that_fails_before_its_first_event_is_a_busbar_attributed_error() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-stream-down";
    let agent = Agent::start_with(
        200,
        STREAMED,
        vec![("content-type", EVENTS.to_string())],
        None,
    )
    .await;
    agent.streams();
    let s = served(instance, &agent.entry("planner", "1h"), false, None);
    approve(&s, "planner").await;

    let (status, body) = answered(
        &s.router,
        rpc("planner", "message/stream", STREAM, Some(&s.token)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "served while it is up: {body}");
    agent.go_down();
    let (status, body) = answered(
        &s.router,
        rpc("planner", "message/stream", STREAM, Some(&s.token)),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
    assert!(
        body.contains(surface("task_resource_type")),
        "the hop's task is named, failed as the engine's `fail_task` failed it: {body}"
    );
    assert!(
        !body.contains("127.0.0.1"),
        "the refusal named the backend endpoint: {body}"
    );
}

/// Ported from busbar-a2a catalogue_tests.rs::scope_decides_visibility_and_a_pool_only_key_sees_nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scope_decides_visibility_and_a_pool_only_key_sees_nothing() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-visibility";
    let mut agent = Agent::start(200, ANSWER).await;
    let s = served(instance, &two_agents(&agent), false, None);
    approve(&s, "planner").await;
    approve(&s, "scout").await;

    let (_, narrowed) = another_caller(&s, "narrowed", Some(vec![agent_scope("planner")]));
    assert_eq!(
        agents_seen(&s, &narrowed).await,
        (StatusCode::OK, vec!["planner".to_string()])
    );
    let (_, pool_only) = another_caller(&s, "pool-only", Some(vec![ScopeRef::pool("fast")]));
    assert_eq!(
        agents_seen(&s, &pool_only).await,
        (StatusCode::OK, Vec::new()),
        "cross-kind admission is fail-closed"
    );
    let (status, body) = answered(
        &s.router,
        rpc("planner", "message/send", SEND, Some(&pool_only)),
    )
    .await;
    assert_not_granted(status, &body, "planner");
    assert!(!agent.relayed(), "nothing was dialled");
}

/// Ported from busbar-a2a catalogue_tests.rs::no_principal_sees_another_principals_agents.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_principal_sees_another_principals_agents() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-principals";
    let mut agent = Agent::start(200, ANSWER).await;
    let s = served(instance, &two_agents(&agent), false, None);
    approve(&s, "planner").await;
    approve(&s, "scout").await;

    let (_, alice) = another_caller(&s, "alice", Some(vec![agent_scope("planner")]));
    let (_, bob) = another_caller(&s, "bob", Some(vec![agent_scope("scout")]));
    let (status, alice_sees) = agents_seen(&s, &alice).await;
    assert_eq!(status, StatusCode::OK);
    let (status, bob_sees) = agents_seen(&s, &bob).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(alice_sees, vec!["planner".to_string()]);
    assert_eq!(bob_sees, vec!["scout".to_string()]);
    assert!(
        alice_sees.iter().all(|a| !bob_sees.contains(a)),
        "one principal's catalogue appeared in the other's: {alice_sees:?} / {bob_sees:?}"
    );

    for (who, token, theirs) in [("alice", &alice, "scout"), ("bob", &bob, "planner")] {
        let (status, body) =
            answered(&s.router, rpc(theirs, "message/send", SEND, Some(token))).await;
        assert_ne!(status, StatusCode::OK, "{who} reached `{theirs}`: {body}");
        assert_not_granted(status, &body, theirs);
        assert!(!agent.relayed(), "{who}: nothing was dialled");
    }
}

/// Ported from busbar-a2a catalogue_tests.rs::a_key_that_is_no_longer_live_sees_no_agent_at_all.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_key_that_is_no_longer_live_sees_no_agent_at_all() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-not-live";
    let mut agent = Agent::start(200, ANSWER).await;
    let s = served(instance, &two_agents(&agent), false, None);
    approve(&s, "planner").await;
    approve(&s, "scout").await;
    assert_eq!(
        agents_seen(&s, &s.token).await,
        (
            StatusCode::OK,
            vec!["planner".to_string(), "scout".to_string()]
        ),
        "the control must pass, or the rows below prove nothing"
    );

    for what in ["deleted", "disabled", "expired"] {
        let (key, token) = another_caller(&s, what, None);
        match what {
            "deleted" => futures::executor::block_on(s.gov.delete_key(&key.id)).expect("deleted"),
            "disabled" => {
                futures::executor::block_on(s.gov.update_key_outcome_async(
                    &key.id,
                    Some(false),
                    None,
                ))
                .expect("a write")
                .expect("the key");
            }
            _ => {
                let mut row = key.clone();
                // Creation is immutable in the actual Store. This caller was minted at the
                // fixture's historical epoch, so a later expiry is valid and already past.
                row.expires_at = Some(row.created_at.saturating_add(1));
                assert!(row.expires_at.unwrap() < busbar_kernel::store::now());
                futures::executor::block_on(
                    s.gov
                        .core_store()
                        .expect("native identity owner")
                        .identity()
                        .put_key(&row),
                )
                .expect("expired");
                futures::executor::block_on(s.gov.refresh_async()).expect("the book reloads");
            }
        }
        let catalogue_read = StatusCode::UNAUTHORIZED;
        let (status, seen) = agents_seen(&s, &token).await;
        assert_eq!(
            (status, seen),
            (catalogue_read, Vec::new()),
            "a {what} key must see no agent"
        );
        let (status, body) = answered(
            &s.router,
            rpc("planner", "message/send", SEND, Some(&token)),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{what}: {body}");
        if what == "expired" {
            let (control, control_token) = another_caller(&s, "expired-refusal-control", None);
            futures::executor::block_on(s.gov.delete_key(&control.id))
                .expect("the control key is deleted");
            let (bad_status, bad_body) = answered(
                &s.router,
                rpc("planner", "message/send", SEND, Some(&control_token)),
            )
            .await;
            assert_eq!(bad_status, StatusCode::UNAUTHORIZED);
            let mut doc: serde_json::Value = serde_json::from_str(&body).expect("an envelope");
            let mut bad: serde_json::Value = serde_json::from_str(&bad_body).expect("an envelope");
            for answer in [&mut doc, &mut bad] {
                answer
                    .as_object_mut()
                    .expect("an error object")
                    .remove("request_id");
            }
            assert_eq!(doc, bad, "stored expiry uses the opaque credential refusal");
        }
        assert!(!agent.relayed(), "{what}: nothing was dialled");
    }
}

/// Ported from busbar-a2a inbound_jws_tests.rs::the_seam_refuses_a_wrong_key_and_a_malformed_key_exactly_as_the_free_function
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_card_signed_by_another_key_than_the_pinned_one_is_refused_and_never_served() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-wrong-key";
    let mut agent = Agent::start(200, ANSWER).await;
    let other = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);
    let section = format!(
        "{}\nimpostor: {{url: 'http://127.0.0.1:{}/impostor', allow_private: true, \
         reverify_ttl: '1h', pin: {{mechanism: jws_issuer_key, key: '{}'}}}}",
        agent.entry("planner", "1h"),
        agent.port,
        key_info(&other)
    );
    let s = served(instance, &section, false, None);

    let (status, preview) = admin(&s, "/agents/planner/connect", "").await;
    assert_eq!(status, StatusCode::OK, "{preview}");
    assert_eq!(preview["state"], "pending", "{preview}");
    assert_eq!(preview["failure"], serde_json::Value::Null, "{preview}");
    assert_eq!(
        preview["fingerprint"],
        agent.fingerprint().as_str(),
        "{preview}"
    );
    approve(&s, "planner").await;
    let (status, body) = answered(
        &s.router,
        rpc("planner", "message/send", SEND, Some(&s.token)),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the correctly pinned registration serves: {body}"
    );
    assert!(agent.relayed(), "the approved control reached the agent");

    let (status, preview) = admin(&s, "/agents/impostor/connect", "").await;
    assert_eq!(status, StatusCode::OK, "{preview}");
    assert_eq!(preview["state"], "error", "{preview}");
    assert!(
        preview["failure"].as_str().is_some_and(
            |f| f.contains("the agent card is signed, but not by the pinned issuer key")
        ),
        "{preview}"
    );
    assert_eq!(
        preview["fingerprint"],
        serde_json::Value::Null,
        "a failed signature offers no fingerprint: {preview}"
    );
    let supplied = serde_json::json!({"fingerprint":agent.fingerprint()}).to_string();
    let (status, refusal) = admin(&s, "/agents/impostor/approve", &supplied).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "the real card's fingerprint cannot approve a wrongly pinned signature: {refusal}"
    );
    assert_eq!(refusal["error"]["code"], "invalid_request", "{refusal}");
    let (status, refusal) = decide_key(&s, "impostor", "approve").await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "generic trust approval cannot approve an unauthenticated card: {refusal}"
    );
    let (status, body) = answered(
        &s.router,
        rpc("impostor", "message/send", SEND, Some(&s.token)),
    )
    .await;
    assert_ne!(status, StatusCode::OK, "{body}");
    assert!(!agent.relayed(), "the impostor was never dialled");
}

/// THE AGENT'S OWN CREDENTIAL THROUGH THE DOOR (`upstream_credential:`): busbar's credential
/// for a registration, bound by the composition, is refreshed off the request path once per lease
/// and presented by the auth kind's per-request call (the plane never holds it).
mod upstream_credential {
    use super::*;

    /// The far agent's answer to every relayed request: a task it is working on, under its own
    /// id, so busbar holds the task live and learns the agent's id for it.
    const WORKING: &str = r#"{"jsonrpc":"2.0","id":1,"result":{"kind":"task","id":"far-1","contextId":"far-c","status":{"state":"working"}}}"#;

    /// AN AGENT THAT KEEPS EVERY REQUEST IT IS SENT, WHOLE — its card fetches included: it
    /// serves its card signed at its origin's well-known path and answers anything else
    /// `answer`.
    struct Recorded {
        port: u16,
        issuer: ed25519_dalek::SigningKey,
        log: Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl Recorded {
        async fn start(answer: &'static str) -> Self {
            let issuer = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
            let log = Arc::new(std::sync::Mutex::new(Vec::new()));
            let held = Arc::new(std::sync::Mutex::new(serde_json::Value::Null));
            let (served_card, signer, kept) = (Arc::clone(&held), issuer.clone(), Arc::clone(&log));
            let (port, _heard) = far_end_over(
                Arc::new(move |request: &str| {
                    kept.lock().expect("the log").push(request.to_string());
                    if request.starts_with("GET ") {
                        let doc = served_card.lock().map(|c| c.clone()).unwrap_or_default();
                        return Some(FarReply::of(200, signed(&doc, &signer).to_string()));
                    }
                    Some(FarReply::of(200, answer.to_string()))
                }),
                None,
            )
            .await;
            *held.lock().expect("the card") = card(port, "plans the work");
            Self { port, issuer, log }
        }

        /// The `agents:` entry registering `planner` here, pinned by its signing key,
        /// re-verified within `reverify_ttl`, stating `upstream_credential` when given.
        fn entry(&self, reverify_ttl: &str, credential: Option<&str>) -> String {
            let credential = credential
                .map(|c| format!(", upstream_credential: {c}"))
                .unwrap_or_default();
            format!(
                "planner: {{url: 'http://127.0.0.1:{}/planner', allow_private: true, \
                 reverify_ttl: '{reverify_ttl}', pin: {{mechanism: jws_issuer_key, key: \
                 '{}'}}{credential}}}",
                self.port,
                key_info(&self.issuer)
            )
        }

        /// Every request it was sent since it was last asked, in order.
        fn take(&self) -> Vec<String> {
            std::mem::take(&mut *self.log.lock().expect("the log"))
        }
    }

    /// The `upstream_credential` block over the secret file `path`, presented at `placement`.
    fn own(path: &std::path::Path, placement: &str) -> String {
        format!(
            "{{secret: {{file: '{}'}}, placement: {placement}, lease_ttl_ms: 60000}}",
            path.display()
        )
    }

    /// A secret file of this cell's own, holding `value`.
    fn secret_file(name: &str, value: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "busbar-serve-agent-cred-{name}-{}",
            std::process::id()
        ));
        std::fs::write(&path, value).expect("write the secret");
        path
    }

    /// REFRESH every served credential now, off the runtime's workers (each lease here is a
    /// minute, so no cell waits on the refresher's own schedule).
    async fn refreshed() {
        tokio::task::spawn_blocking(crate::root::door_steps::refresh_credentials)
            .await
            .expect("the refresh");
    }

    /// ROTATE the secret at `path` to `value` as a secret store does: written aside, renamed
    /// over it.
    fn rotate(path: &std::path::Path, value: &str) {
        let aside = path.with_extension("rotating");
        std::fs::write(&aside, value).expect("write the rotated secret");
        std::fs::rename(&aside, path).expect("swap it in");
    }

    /// The value of head field `name` in the whole request `request` (case-insensitive).
    fn header(request: &str, name: &str) -> Option<String> {
        let head = request.split("\r\n\r\n").next()?;
        head.lines().skip(1).find_map(|line| {
            let (n, v) = line.split_once(':')?;
            n.trim()
                .eq_ignore_ascii_case(name)
                .then(|| v.trim().to_string())
        })
    }

    /// The card fetches (`GET`) and the other requests (`POST`) of `log`.
    fn split(log: Vec<String>) -> (Vec<String>, Vec<String>) {
        log.into_iter().partition(|r| r.starts_with("GET "))
    }

    /// Every card fetch in `gets` carries no credential at all.
    fn no_credential_on(gets: &[String], at: &str) {
        for get in gets {
            assert_eq!(header(get, "authorization"), None, "{at}: {get}");
            assert_eq!(header(get, "x-api-key"), None, "{at}: {get}");
        }
    }

    /// The busbar task id a relayed answer names.
    fn task_of(body: &str) -> String {
        let doc: serde_json::Value = serde_json::from_str(body).expect("an answer");
        doc["result"]["id"]
            .as_str()
            .unwrap_or_else(|| panic!("no task in {body}"))
            .to_string()
    }

    /// `placement: bearer`: the agent's relayed hop, its extended card read through the relay,
    /// and busbar's own originated requests each carry `authorization: Bearer <secret>`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_agents_own_bearer_rides_its_hops_and_never_its_card_fetches() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-agent-cred-bearer";
        let path = secret_file("bearer", "vendor-token-1\n");
        let agent = Recorded::start(WORKING).await;
        let s = served(
            instance,
            &agent.entry("0s", Some(&own(&path, "bearer"))),
            false,
            None,
        );
        approve(&s, "planner").await;
        let (gets, posts) = split(agent.take());
        assert!(!gets.is_empty(), "connect fetched the card");
        assert!(posts.is_empty(), "{posts:?}");
        no_credential_on(&gets, "connect's card fetch");

        let bearer = Some("Bearer vendor-token-1".to_string());
        let (status, body) = answered(
            &s.router,
            rpc("planner", "message/send", SEND, Some(&s.token)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let task = task_of(&body);
        let (gets, posts) = split(agent.take());
        assert!(!gets.is_empty(), "verify-on-call re-fetched the card");
        no_credential_on(&gets, "verify-on-call's card fetch");
        assert_eq!(posts.len(), 1, "{posts:?}");
        assert_eq!(header(&posts[0], "authorization"), bearer, "{}", posts[0]);
        assert!(
            !posts[0].contains(&s.token),
            "never the caller's token: {}",
            posts[0]
        );

        let (status, body) = answered(
            &s.router,
            rpc("planner", "GetExtendedAgentCard", "{}", Some(&s.token)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (gets, posts) = split(agent.take());
        no_credential_on(&gets, "verify-on-call's card fetch");
        assert_eq!(posts.len(), 1, "the extended card, relayed: {posts:?}");
        assert!(posts[0].contains("GetExtendedAgentCard"), "{}", posts[0]);
        assert_eq!(header(&posts[0], "authorization"), bearer, "{}", posts[0]);

        let (status, body) = answered(
            &s.router,
            rpc("planner", "tasks/list", "{}", Some(&s.token)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (_, posts) = split(agent.take());
        assert!(
            posts.iter().any(|p| p.contains("ListTasks")),
            "busbar refreshed the agent's task list: {posts:?}"
        );
        for post in &posts {
            assert_eq!(header(post, "authorization"), bearer, "{post}");
        }

        let set = format!(
            r#"{{"taskId":"{task}","pushNotificationConfig":{{"url":"https://93.184.215.14/cb"}}}}"#
        );
        let (status, body) = answered(
            &s.router,
            rpc(
                "planner",
                "tasks/pushNotificationConfig/set",
                &set,
                Some(&s.token),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (_, posts) = split(agent.take());
        let callback = v03_callback_token(&posts, "far-1");
        assert_ne!(
            callback, "vendor-token-1",
            "the callback has its own capability"
        );
        assert_ne!(callback, s.token, "never the caller's credential");
        for post in &posts {
            assert_eq!(header(post, "authorization"), bearer, "{post}");
        }
        let _ = std::fs::remove_file(&path);
    }

    /// `placement: {header: X-API-Key}`: the relayed hop carries the secret verbatim in that
    /// header and no `authorization`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_named_header_placement_carries_the_secret_verbatim() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-agent-cred-header";
        let path = secret_file("header", "abc123");
        let agent = Recorded::start(WORKING).await;
        let s = served(
            instance,
            &agent.entry("1h", Some(&own(&path, "{header: X-API-Key}"))),
            false,
            None,
        );
        approve(&s, "planner").await;
        no_credential_on(&split(agent.take()).0, "connect's card fetch");
        let (status, body) = answered(
            &s.router,
            rpc("planner", "message/send", SEND, Some(&s.token)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (_, posts) = split(agent.take());
        assert_eq!(posts.len(), 1, "{posts:?}");
        assert_eq!(
            header(&posts[0], "x-api-key").as_deref(),
            Some("abc123"),
            "{}",
            posts[0]
        );
        assert_eq!(header(&posts[0], "authorization"), None, "{}", posts[0]);
        let _ = std::fs::remove_file(&path);
    }

    /// R5 (coordinator ruling: as predev): an agent registered with NO `upstream_credential` is
    /// dialled unauthenticated — no credential header on any request, card fetch or hop.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_agent_with_no_upstream_credential_is_dialled_with_none() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-agent-cred-none";
        let agent = Recorded::start(WORKING).await;
        let s = served(instance, &agent.entry("1h", None), false, None);
        approve(&s, "planner").await;
        let (status, body) = answered(
            &s.router,
            rpc("planner", "message/send", SEND, Some(&s.token)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (gets, posts) = split(agent.take());
        assert_eq!(posts.len(), 1, "{posts:?}");
        no_credential_on(&gets, "a card fetch");
        no_credential_on(&posts, "the relayed hop");
    }

    /// EACH AGENT'S OWN CREDENTIAL, NEVER ITS NEIGHBOUR'S (predev `creds.rs` `Lease::header_for`:
    /// a lease minted for one agent refuses a hop to another, `LeaseError::WrongAgent`; R5: an
    /// agent with no `upstream_credential` is dialled with none).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn agents_sharing_an_origin_each_present_only_their_own_credential() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-agent-cred-shared-origin";
        let planner = secret_file("shared-planner", "planner-secret");
        let summarizer = secret_file("shared-summarizer", "summarizer-secret");
        let agent = Recorded::start(WORKING).await;
        let entry = |name: &str, credential: Option<String>| {
            let credential = credential
                .map(|c| format!(", upstream_credential: {c}"))
                .unwrap_or_default();
            format!(
                "{name}: {{url: 'http://127.0.0.1:{}/{name}', allow_private: true, \
                 reverify_ttl: '1h', pin: {{mechanism: jws_issuer_key, key: \
                 '{}'}}{credential}}}",
                agent.port,
                key_info(&agent.issuer)
            )
        };
        let section = [
            entry("planner", Some(own(&planner, "bearer"))),
            entry("summarizer", Some(own(&summarizer, "bearer"))),
            entry("scout", None),
        ]
        .join("\n");
        let s = served(instance, &section, false, None);
        for (name, expected) in [
            ("planner", Some("Bearer planner-secret".to_string())),
            ("summarizer", Some("Bearer summarizer-secret".to_string())),
            ("scout", None),
        ] {
            approve(&s, name).await;
            no_credential_on(&split(agent.take()).0, "connect's card fetch");
            let at = format!("/{name} ");
            let mut heard = Vec::new();
            let (status, body) =
                answered(&s.router, rpc(name, "message/send", SEND, Some(&s.token))).await;
            assert_eq!(status, StatusCode::OK, "{name}: {body}");
            let task = task_of(&body);
            heard.extend(split(agent.take()).1);
            let (status, body) =
                answered(&s.router, rpc(name, "tasks/list", "{}", Some(&s.token))).await;
            assert_eq!(status, StatusCode::OK, "{name}: {body}");
            heard.extend(split(agent.take()).1);
            let set = format!(
                r#"{{"taskId":"{task}","pushNotificationConfig":{{"url":"https://93.184.215.14/cb"}}}}"#
            );
            let (status, body) = answered(
                &s.router,
                rpc(
                    name,
                    "tasks/pushNotificationConfig/set",
                    &set,
                    Some(&s.token),
                ),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{name}: {body}");
            heard.extend(split(agent.take()).1);
            assert!(
                heard.iter().any(|p| p.contains("ListTasks")),
                "{name}: busbar refreshed the agent's task list: {heard:?}"
            );
            let callback = v03_callback_token(&heard, "far-1");
            assert_ne!(callback, s.token, "{name}: never the caller's credential");
            if let Some(credential) = &expected {
                assert_ne!(
                    format!("Bearer {callback}"),
                    *credential,
                    "{name}: the callback has its own capability"
                );
            }
            for post in &heard {
                assert!(post.contains(&at), "{name}: only its own path: {post}");
                assert_eq!(header(post, "authorization"), expected, "{name}: {post}");
                assert_eq!(header(post, "x-api-key"), None, "{name}: {post}");
            }
        }
        let _ = std::fs::remove_file(&planner);
        let _ = std::fs::remove_file(&summarizer);
    }

    /// ROTATION: the secret's source changes between two hops; a hop before the next refresh
    /// still presents what the last refresh left (no hop resolves a secret: ARCHITECT ruling on
    /// #787), and the first hop after the next refresh presents the new value.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_rotated_secret_is_presented_on_the_first_hop_after_the_next_refresh() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-agent-cred-rotate";
        let path = secret_file("rotate", "before-rotation");
        let agent = Recorded::start(WORKING).await;
        let s = served(
            instance,
            &agent.entry("1h", Some(&own(&path, "bearer"))),
            false,
            None,
        );
        approve(&s, "planner").await;
        let _ = agent.take();
        let mut last = "before-rotation";
        for value in ["before-rotation", "after-rotation"] {
            rotate(&path, value);
            let (status, body) = answered(
                &s.router,
                rpc("planner", "message/send", SEND, Some(&s.token)),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{body}");
            let (_, posts) = split(agent.take());
            assert_eq!(posts.len(), 1, "{posts:?}");
            assert_eq!(
                header(&posts[0], "authorization"),
                Some(format!("Bearer {last}")),
                "before the refresh: {}",
                posts[0]
            );
            refreshed().await;
            last = value;
            let (status, body) = answered(
                &s.router,
                rpc("planner", "message/send", SEND, Some(&s.token)),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{body}");
            let (_, posts) = split(agent.take());
            assert_eq!(posts.len(), 1, "{posts:?}");
            assert_eq!(
                header(&posts[0], "authorization"),
                Some(format!("Bearer {value}")),
                "{}",
                posts[0]
            );
        }
        let _ = std::fs::remove_file(&path);
    }

    /// A CREDENTIAL THAT STOPS RESOLVING (its secret file removed) refuses every hop after the
    /// next refresh, in the served engine's bytes, and dials nothing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_vanished_secret_refuses_each_hop_after_the_next_refresh() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-agent-cred-vanished";
        let path = secret_file("vanished", "soon-gone");
        let agent = Recorded::start(WORKING).await;
        let s = served(
            instance,
            &agent.entry("1h", Some(&own(&path, "bearer"))),
            false,
            None,
        );
        approve(&s, "planner").await;
        let (status, body) = answered(
            &s.router,
            rpc("planner", "message/send", SEND, Some(&s.token)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "served while it resolves: {body}");
        let live = task_of(&body);
        std::fs::remove_file(&path).expect("the secret vanishes");
        refreshed().await;
        let _ = agent.take();

        let info = serde_json::json!({
            "@type": "type.googleapis.com/google.rpc.ErrorInfo",
            "domain": surface("error_info_domain"),
            "reason": "INVALID_AGENT_RESPONSE",
        });
        let (status, body) = answered(
            &s.router,
            rpc("planner", "message/send", SEND, Some(&s.token)),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
        let doc: serde_json::Value = serde_json::from_str(&body).expect("the envelope");
        let failed = doc["error"]["data"][1]["resourceName"]
            .as_str()
            .unwrap_or_else(|| panic!("the refusal names its task: {body}"))
            .to_string();
        assert_eq!(
            doc,
            serde_json::json!({ "jsonrpc": "2.0", "id": 1, "error": {
                "code": -32006,
                "message": "the backend agent did not complete this task",
                "data": [info.clone(), {
                    "@type": "type.googleapis.com/google.rpc.ResourceInfo",
                    "resourceType": surface("task_resource_type"),
                    "resourceName": failed,
                }],
            } }),
            "{body}"
        );

        let (status, body) = answered(
            &s.router,
            rpc(
                "planner",
                "tasks/get",
                &format!(r#"{{"id":"{failed}"}}"#),
                Some(&s.token),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&body).expect("the envelope"),
            serde_json::json!({ "jsonrpc": "2.0", "id": 1, "error": {
                "code": -32006,
                "message": "the backend agent did not complete this task",
                "data": [info.clone(), {
                    "@type": "type.googleapis.com/google.rpc.ResourceInfo",
                    "resourceType": surface("task_resource_type"),
                    "resourceName": failed,
                }],
            } }),
            "{body}"
        );

        let state = listed_state(&s, &failed).await;
        assert!(
            ["failed", "TASK_STATE_FAILED"].contains(&state.as_str()),
            "the task row is closed failed: {state}"
        );

        let (status, body) = answered(
            &s.router,
            rpc("planner", "GetExtendedAgentCard", "{}", Some(&s.token)),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&body).expect("the envelope"),
            serde_json::json!({ "jsonrpc": "2.0", "id": 1, "error": {
                "code": -32006,
                "message": "the extended agent card could not be fetched",
                "data": [info],
            } }),
            "{body}"
        );

        let (status, body) = answered(
            &s.router,
            rpc("planner", "tasks/list", "{}", Some(&s.token)),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the caller's own answer stands: {body}"
        );
        let set = format!(
            r#"{{"taskId":"{live}","pushNotificationConfig":{{"url":"https://93.184.215.14/cb"}}}}"#
        );
        let (status, body) = answered(
            &s.router,
            rpc(
                "planner",
                "tasks/pushNotificationConfig/set",
                &set,
                Some(&s.token),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the caller's own answer stands: {body}"
        );
        assert_eq!(
            agent.take(),
            Vec::<String>::new(),
            "no hop reached the agent"
        );
    }

    /// A SECRET'S SOURCE NEVER REACHES A CALLER (the root's secret-source scan, coordinator ruling
    /// 2026-10-07): a credential whose source goes away refuses the first hop after the next
    /// refresh without naming that source.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_credential_that_stops_resolving_reaches_the_caller_without_its_source() {
        let _one = PUBLISHING.lock().await;
        let path = std::env::temp_dir()
            .join(format!("busbar-a2a-upstream-file-{}", std::process::id(),))
            .to_string_lossy()
            .into_owned();
        let _ = std::fs::remove_file(&path);
        let (instance, credential, secret) = (
            "serve-agent-cred-source-file",
            format!("{{secret: {{file: '{path}'}}, placement: bearer, lease_ttl_ms: 60000}}"),
            serde_json::from_value::<busbar_contract::secret_ref::SecretRef>(
                serde_json::json!({ "file": path.clone() }),
            )
            .expect("a sugar reference"),
        );
        {
            std::fs::write(&path, "agent-own-token").expect("write the secret");
            let agent = Recorded::start(WORKING).await;
            let s = served(instance, &agent.entry("1h", Some(&credential)), false, None);
            approve(&s, "planner").await;
            let (status, body) = answered(
                &s.router,
                rpc("planner", "message/send", SEND, Some(&s.token)),
            )
            .await;
            assert_eq!(
                status,
                StatusCode::OK,
                "{instance}: served while it resolves: {body}"
            );
            let _ = std::fs::remove_file(&path);
            refreshed().await;
            let needles = || {
                let mut words = vec![
                    "environment variable".to_string(),
                    "is unset".to_string(),
                    "no such file".to_string(),
                    format!("secret {}", busbar_contract::secret_ref::SECRET_MODULE_FILE),
                    secret.describe(),
                ];
                words.extend(
                    secret
                        .settings
                        .values()
                        .filter_map(serde_json::Value::as_str)
                        .map(str::to_string),
                );
                words
            };
            let refusal = busbar_kernel::config::secret::resolve_linked_string_at_config(
                &secret,
                &busbar_contract::config_time::ConfigScope::config_time(),
            )
            .expect_err("the source reference no longer resolves");
            assert!(
                needles().iter().any(|word| !word.is_empty()
                    && refusal
                        .to_ascii_lowercase()
                        .contains(&word.to_ascii_lowercase())),
                "the source's own refusal names it, so the scan has something to find: {refusal}"
            );
            let response = {
                use tower::ServiceExt as _;
                s.router
                    .clone()
                    .oneshot(rpc("planner", "message/send", SEND, Some(&s.token)))
                    .await
                    .expect("the router answers")
            };
            let status = response.status();
            let headers = response.headers().clone();
            let body = axum::body::to_bytes(response.into_body(), 1 << 16)
                .await
                .expect("the body");
            assert_ne!(status, StatusCode::OK, "{instance}: the hop is refused");
            let mut rendered = format!(
                "{} {}\n",
                status.as_str(),
                status.canonical_reason().unwrap_or_default()
            );
            for (name, value) in &headers {
                rendered.push_str(&format!(
                    "{}: {}\n",
                    name.as_str(),
                    String::from_utf8_lossy(value.as_bytes())
                ));
            }
            rendered.push('\n');
            rendered.push_str(&String::from_utf8_lossy(&body));
            let found: Vec<_> = needles()
                .into_iter()
                .filter(|word| {
                    !word.is_empty()
                        && rendered
                            .to_ascii_lowercase()
                            .contains(&word.to_ascii_lowercase())
                })
                .collect();
            assert!(
                found.is_empty(),
                "{instance}: the caller was handed the secret's source {found:?}:\n{rendered}"
            );
        }
    }
}

/// One length-prefixed message (`frame`'s bytes), as a gRPC far end writes it.
fn grpc_framed(message: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8];
    out.extend_from_slice(&u32::try_from(message.len()).expect("small").to_be_bytes());
    out.extend_from_slice(message);
    out
}

/// A send's answer, its protobuf written out field by field: a task (field 1) whose id
/// (field 1) is `far-task` and whose status (field 3) is working (state field 1, `2`).
fn grpc_working_answer() -> Vec<u8> {
    let status = [0x08, 0x02];
    let mut task = vec![0x0a, 8];
    task.extend_from_slice(b"far-task");
    task.extend_from_slice(&[0x1a, 2]);
    task.extend_from_slice(&status);
    let mut answer = vec![0x0a, u8::try_from(task.len()).expect("small")];
    answer.extend_from_slice(&task);
    grpc_framed(&answer)
}

/// A gRPC AGENT ON LOOPBACK, pinned by its signing key: its card (naming only the gRPC binding)
/// at its origin's well-known path over HTTP/1.1, and every rpc on the same port over HTTP/2.
struct GrpcAgent {
    port: u16,
    heard: tokio::sync::mpsc::UnboundedReceiver<(String, Vec<u8>)>,
    issuer: ed25519_dalek::SigningKey,
}

impl GrpcAgent {
    async fn start(answer: Vec<u8>) -> Self {
        Self::ending(answer, "0").await
    }

    /// The agent, each rpc answered `answer` (no message when empty) and its trailers stating
    /// `grpc-status: <status>`.
    async fn ending(answer: Vec<u8>, status: &'static str) -> Self {
        Self::serving(answer, status, 200, None).await
    }

    /// [`GrpcAgent::ending`], each rpc answered at the HTTP status `http` (any other than `200`
    /// a plain refusal, `denied`, no gRPC message or trailers), and its card the one an agent on
    /// `card_port` serves (its own port's when `None`).
    async fn serving(
        answer: Vec<u8>,
        status: &'static str,
        http: u16,
        card_port: Option<u16>,
    ) -> Self {
        use http_body_util::BodyExt as _;
        type Frames = Vec<Result<http_body::Frame<bytes::Bytes>, std::convert::Infallible>>;
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a loopback port");
        let port = listener.local_addr().expect("its address").port();
        let card_port = card_port.unwrap_or(port);
        let mut held = card(card_port, "plans the work");
        held["supportedInterfaces"] = serde_json::json!([{
            "url": format!("http://127.0.0.1:{card_port}/planner"),
            "protocolBinding": surface("grpc_binding"),
            "protocolVersion": "1.0",
        }]);
        let served = signed(&held, &issuer).to_string();
        let (sent, heard) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                let (sent, served, answer) = (sent.clone(), served.clone(), answer.clone());
                tokio::spawn(async move {
                    let service = hyper::service::service_fn(
                        move |req: hyper::Request<hyper::body::Incoming>| {
                            let (sent, served, answer) =
                                (sent.clone(), served.clone(), answer.clone());
                            async move {
                                let get = req.method() == hyper::Method::GET;
                                let path = req.uri().path().to_string();
                                let body = req
                                    .into_body()
                                    .collect()
                                    .await
                                    .map(|c| c.to_bytes().to_vec())
                                    .unwrap_or_default();
                                let (media, frames): (&str, Frames) = if !get && http != 200 {
                                    let _ = sent.send((path, body));
                                    (
                                        "text/plain",
                                        vec![Ok(http_body::Frame::data(
                                            bytes::Bytes::from_static(b"denied"),
                                        ))],
                                    )
                                } else if get {
                                    (
                                        "application/json",
                                        vec![Ok(http_body::Frame::data(bytes::Bytes::from(
                                            served,
                                        )))],
                                    )
                                } else {
                                    let _ = sent.send((path, body));
                                    let mut trailers = http::HeaderMap::new();
                                    trailers.insert(
                                        "grpc-status",
                                        http::HeaderValue::from_static(status),
                                    );
                                    let mut frames: Frames = Vec::new();
                                    if !answer.is_empty() {
                                        frames.push(Ok(http_body::Frame::data(
                                            bytes::Bytes::from(answer),
                                        )));
                                    }
                                    frames.push(Ok(http_body::Frame::trailers(trailers)));
                                    ("application/grpc", frames)
                                };
                                hyper::Response::builder()
                                    .status(if get { 200 } else { http })
                                    .header("content-type", media)
                                    .body(http_body_util::StreamBody::new(futures::stream::iter(
                                        frames,
                                    )))
                            }
                        },
                    );
                    let _ = hyper_util::server::conn::auto::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    )
                    .serve_connection(hyper_util::rt::TokioIo::new(socket), service)
                    .await;
                });
            }
        });
        Self {
            port,
            heard,
            issuer,
        }
    }

    /// The `agents:` entry registering `name` at this agent's path `/<name>`, pinned by its
    /// signing key.
    fn entry(&self, name: &str) -> String {
        format!(
            "{name}: {{url: 'http://127.0.0.1:{}/{name}', allow_private: true, reverify_ttl: \
             '1h', pin: {{mechanism: jws_issuer_key, key: '{}'}}}}",
            self.port,
            key_info(&self.issuer)
        )
    }
}

/// THE DOOR DIALS A gRPC AGENT (the engine's `grpc_client_issues_send_message`, end to end
/// through the composition): an agent whose card names only the gRPC binding is approved over its
/// card and a relayed `SendMessage` reaches it over HTTP/2 on the door's gRPC need.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_agent_whose_card_names_only_grpc_is_dialled_over_grpc() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-grpc";
    let mut agent = GrpcAgent::start(grpc_working_answer()).await;
    let s = served(instance, &agent.entry("planner"), false, None);
    approve(&s, "planner").await;
    let params = r#"{"message":{"messageId":"m-1","role":"ROLE_USER","parts":[{"text":"PLAN THE MIGRATION"}]}}"#;
    let (status, body) = answered(
        &s.router,
        rpc("planner", "SendMessage", params, Some(&s.token)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (path, sent) = agent
        .heard
        .try_recv()
        .unwrap_or_else(|_| panic!("the agent was not dialled over gRPC: {body}"));
    assert_eq!(path, format!("{}/SendMessage", surface("grpc_service")));
    assert!(sent.len() > 5, "a length-prefixed message: {sent:?}");
    assert_eq!(sent[0], 0, "no compression");
    let len = u32::from_be_bytes([sent[1], sent[2], sent[3], sent[4]]) as usize;
    assert_eq!(sent.len(), 5 + len, "exactly one length-prefixed message");
    let content = b"PLAN THE MIGRATION";
    assert!(
        sent.windows(content.len()).any(|w| w == content),
        "the caller's content survives the transcode into the request message"
    );
    let doc: serde_json::Value = serde_json::from_str(&body).expect("an answer");
    assert_eq!(doc["id"], 1);
    assert_eq!(
        doc["result"]["task"]["status"]["state"], "TASK_STATE_WORKING",
        "{body}"
    );
    assert_ne!(
        doc["result"]["task"]["id"], "far-task",
        "the answer leaves under busbar's task identity: {body}"
    );
}

/// An A2A hop uses the host's declared gRPC need and the gRPC transport end to end.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_a2a_hop_rides_the_hosts_grpc_need_to_an_in_process_grpc_agent() {
    use root_facts::{NEED_AGENT, NEED_GRPC};
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-grpc-need";
    let mut agent = GrpcAgent::start(grpc_working_answer()).await;
    let s = served(instance, &agent.entry("planner"), false, None);
    approve(&s, "planner").await;
    let params = r#"{"message":{"messageId":"m-174","role":"ROLE_USER","parts":[{"text":"ROUTE THE ROW"}]}}"#;
    let (status, body) = answered(
        &s.router,
        rpc("planner", "SendMessage", params, Some(&s.token)),
    )
    .await;

    let (path, sent) = agent
        .heard
        .try_recv()
        .unwrap_or_else(|_| panic!("the hop never reached the gRPC agent ({status}): {body}"));
    assert_eq!(path, format!("/{}/SendMessage", root_facts::SERVICE_NAME));
    assert!(sent.len() > 5, "a length-prefixed message: {sent:?}");
    assert_eq!(sent[0], 0, "no compression");
    let len = u32::from_be_bytes([sent[1], sent[2], sent[3], sent[4]]) as usize;
    assert_eq!(sent.len(), 5 + len, "exactly one length-prefixed message");
    let message = root_facts::read_send_message_request(&sent[5..])
        .unwrap_or_else(|e| panic!("the far end reads a SendMessageRequest: {e}"));
    assert_eq!(message.message_id, "m-174");
    assert_eq!(message.role, root_facts::ROLE_USER);
    assert_eq!(
        message.texts,
        ["ROUTE THE ROW"],
        "the caller's one text part"
    );

    assert_eq!(status, StatusCode::OK, "{body}");
    let doc: serde_json::Value = serde_json::from_str(&body).expect("an answer");
    assert_eq!(doc["id"], 1, "{body}");
    assert_eq!(
        doc["result"]["task"]["status"]["state"], "TASK_STATE_WORKING",
        "{body}"
    );

    let opened = s.riding.opened();
    let &(owner, need) = opened
        .iter()
        .find(|(_, n)| n.0 == NEED_GRPC)
        .unwrap_or_else(|| panic!("no open on the gRPC need; the walk opened {opened:?}"));
    assert!(
        opened.iter().all(|(_, n)| n.0 != NEED_AGENT),
        "the hop rode the agent's http need: {opened:?}"
    );
    let spec = s
        .riding
        .inner
        .declared_spec(owner, need)
        .expect("the door declared its gRPC need on the connector");
    assert_eq!(spec.transport, root_facts::FRAMED_TRANSPORT);
    assert!(
        s.riding.inner.framer_for(&spec.transport).is_some(),
        "a loaded transport serves the gRPC need's scheme"
    );
}

/// A gRPC CALLER IS ANSWERED THROUGH ITS STREAM'S FRAMER (SEAM-4l): `SendMessage` over the gRPC
/// binding goes out under the listener's `200`, its one message length-prefixed, and the call
/// closes with `grpc-status: 0` in the trailers, as predev's gRPC line answered it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_grpc_callers_send_message_is_answered_ok_with_its_status_in_the_trailers() {
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-grpc-inbound";

    let mut agent = Agent::start(
        200,
        r#"{"jsonrpc":"2.0","id":1,"result":{"task":{"id":"far-task","contextId":"far-ctx","status":{"state":"TASK_STATE_WORKING"}}}}"#,
    )
    .await;
    let s = served(instance, &agent.entry("planner", "1h"), false, None);
    approve(&s, "planner").await;
    let message = root_facts::send_message_request("m-1", "PLAN THE MIGRATION");
    let mut body = vec![0u8];
    body.extend_from_slice(&u32::try_from(message.len()).expect("small").to_be_bytes());
    body.extend_from_slice(&message);
    let req = axum::http::Request::builder()
        .method("POST")
        .uri(format!("{}/SendMessage", surface("grpc_service")))
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .header("authorization", format!("Bearer {}", s.token))
        .body(axum::body::Body::from(body))
        .expect("a request");
    let response = s
        .router
        .clone()
        .oneshot(req)
        .await
        .expect("the router answers");
    let (parts, body) = response.into_parts();
    let collected = body.collect().await.expect("the answer");
    let trailers = collected.trailers().cloned();
    let bytes = collected.to_bytes();
    assert_eq!(
        parts.status,
        StatusCode::OK,
        "{:?} {bytes:?}",
        parts.headers
    );
    assert_eq!(
        parts
            .headers
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("application/grpc"),
        "the head states the gRPC media type, as predev's gRPC line did: {:?}",
        parts.headers
    );
    let trailers = trailers.expect("the call closes in its trailers");
    assert_eq!(
        trailers.get("grpc-status").and_then(|v| v.to_str().ok()),
        Some("0"),
        "{trailers:?}"
    );
    assert!(
        bytes.len() > 5 && bytes[0] == 0,
        "one length-prefixed message: {bytes:?}"
    );
    let len = u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as usize;
    assert_eq!(bytes.len(), 5 + len, "exactly one message");
    let state = root_facts::send_message_response_task_state(&bytes[5..])
        .expect("a SendMessageResponse carrying a task");
    assert_eq!(
        state,
        root_facts::TASK_STATE_WORKING,
        "the agent's answer reaches the caller: {bytes:?}"
    );
    assert!(agent.relayed(), "the agent was reached");
}

/// A gRPC CALL REFUSED BEFORE ITS LINE WAS READ IS REFUSED ON THE gRPC LINE: a `SendMessage`
/// naming an `a2a-version` this endpoint does not speak is `FAILED_PRECONDITION`, with typed
/// `VERSION_NOT_SUPPORTED` details, trailers-only under the listener's `200`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_grpc_call_naming_a_version_this_endpoint_does_not_speak_is_failed_precondition() {
    use base64::Engine as _;
    use http_body_util::BodyExt as _;
    use root_facts::Field::{Bytes, Varint};
    use tower::ServiceExt as _;
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-grpc-version";
    let mut agent = Agent::start(200, ANSWER).await;
    let s = served(instance, &agent.entry("planner", "1h"), false, None);
    approve(&s, "planner").await;
    let message = root_facts::send_message_request("m-1", "PLAN THE MIGRATION");
    let mut body = vec![0u8];
    body.extend_from_slice(&u32::try_from(message.len()).expect("small").to_be_bytes());
    body.extend_from_slice(&message);
    let req = axum::http::Request::builder()
        .method("POST")
        .uri(format!("{}/SendMessage", surface("grpc_service")))
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .header("a2a-version", "99.0")
        .header("authorization", format!("Bearer {}", s.token))
        .body(axum::body::Body::from(body))
        .expect("a request");
    let response = s
        .router
        .clone()
        .oneshot(req)
        .await
        .expect("the router answers");
    let (parts, body) = response.into_parts();
    let collected = body.collect().await.expect("the answer");
    let trailers = collected.trailers().cloned();
    let bytes = collected.to_bytes();
    assert_eq!(
        parts.status,
        StatusCode::OK,
        "{:?} {bytes:?}",
        parts.headers
    );
    assert_eq!(
        parts
            .headers
            .get("grpc-status")
            .and_then(|v| v.to_str().ok()),
        Some("9"),
        "trailers-only, the version error's status: {:?}",
        parts.headers
    );
    let details = parts.headers["grpc-status-details-bin"]
        .to_str()
        .expect("base64 status details");
    let details = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(details)
        .expect("a protobuf Status");
    let status = root_facts::fields(&details).expect("Status fields");
    let [(1, Varint(9)), (2, Bytes(_)), (3, Bytes(info))] = status.as_slice() else {
        panic!("FAILED_PRECONDITION with one typed detail: {status:?}");
    };
    let info = root_facts::fields(info).expect("Any fields");
    let [(1, Bytes(kind)), (2, Bytes(value))] = info.as_slice() else {
        panic!("one typed ErrorInfo: {info:?}");
    };
    assert_eq!(kind, b"type.googleapis.com/google.rpc.ErrorInfo");
    assert_eq!(
        root_facts::fields(value).expect("ErrorInfo fields"),
        vec![
            (1, Bytes(b"VERSION_NOT_SUPPORTED".to_vec())),
            (2, Bytes(surface("error_info_domain").as_bytes().to_vec())),
        ]
    );
    assert!(bytes.is_empty(), "no message: {bytes:?}");
    assert!(trailers.is_none(), "one header block: {trailers:?}");
    assert!(!agent.relayed(), "a refused call dials no agent");
}

/// A gRPC CALL THAT ENDS IN AN ERROR BEFORE ANY MESSAGE CLOSES TRAILERS-ONLY, in predev's bytes:
/// `GetTask` naming a task its agent refuses (`TaskNotFoundError`) is answered as one header block
/// with no body and no trailers.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_grpc_call_refused_before_any_message_closes_trailers_only_as_predev() {
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-grpc-trailers-only";

    let mut agent = Agent::start(
        200,
        r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32001,"message":"no task"}}"#,
    )
    .await;
    let s = served(instance, &agent.entry("planner", "1h"), false, None);
    approve(&s, "planner").await;
    let message = root_facts::get_task_request("no-such-task");
    let mut body = vec![0u8];
    body.extend_from_slice(&u32::try_from(message.len()).expect("small").to_be_bytes());
    body.extend_from_slice(&message);
    let req = axum::http::Request::builder()
        .method("POST")
        .uri(format!("{}/GetTask", surface("grpc_service")))
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .header("authorization", format!("Bearer {}", s.token))
        .body(axum::body::Body::from(body))
        .expect("a request");
    let response = s
        .router
        .clone()
        .oneshot(req)
        .await
        .expect("the router answers");
    let (parts, body) = response.into_parts();
    let collected = body.collect().await.expect("the answer");
    let trailers = collected.trailers().cloned();
    let bytes = collected.to_bytes();
    assert_eq!(
        parts.status,
        StatusCode::OK,
        "{:?} {bytes:?}",
        parts.headers
    );
    let head: Vec<(String, String)> = parts
        .headers
        .iter()
        .filter(|(n, _)| n.as_str() != "date")
        .map(|(n, v)| (n.to_string(), v.to_str().unwrap_or_default().to_string()))
        .collect();
    let names: Vec<&str> = head.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(
        &names[..4],
        &[
            "content-type",
            "grpc-status",
            "grpc-message",
            "grpc-status-details-bin"
        ],
        "ONE header block, in predev's order: {head:?}"
    );
    assert_eq!(head[0].1, "application/grpc", "{head:?}");
    assert_eq!(head[1].1, "5", "NOT_FOUND: {head:?}");
    assert!(bytes.is_empty(), "no message: {bytes:?}");
    assert!(
        trailers.is_none(),
        "trailers-only, no trailer block: {trailers:?}"
    );
    assert!(
        !agent.relayed(),
        "an unheld task is refused locally without probing the agent"
    );
}

/// MONEY (this cell touches money: it reads the units' lines on the node's book). A RELAYED
/// gRPC CALL LEDGERS THE BYTES PREDEV LEDGERED, AND A RECORD-SERVED ANSWER LEDGERS NONE.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_grpc_hop_ledgers_predevs_bytes_and_a_record_served_answer_none() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-grpc-billed";
    let answer = grpc_working_answer();
    let mut agent = GrpcAgent::start(answer.clone()).await;
    let s = served(instance, &agent.entry("planner"), false, None);
    approve(&s, "planner").await;
    let params = r#"{"message":{"messageId":"m-1","role":"ROLE_USER","parts":[{"text":"PLAN THE MIGRATION"}]}}"#;
    let (status, body) = answered(
        &s.router,
        rpc("planner", "SendMessage", params, Some(&s.token)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, sent) = agent
        .heard
        .try_recv()
        .unwrap_or_else(|_| panic!("the agent was not dialled over gRPC: {body}"));
    let lines = caller_counts(&s);
    assert_eq!(lines.len(), 1, "one line for the relayed unit: {lines:?}");
    assert_eq!(
        counted(&lines[0], surface("bytes_class")),
        (sent.len() + answer.len()) as u64,
        "the prefixed request the agent read plus the prefixed answer, no trailer: {lines:?}"
    );
    let (status, body) = answered(
        &s.router,
        rpc("planner", "tasks/list", "{}", Some(&s.token)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "answered from the records: {body}");

    while let Ok((path, sent)) = agent.heard.try_recv() {
        assert!(
            path.ends_with("/ListTasks"),
            "the list relayed {path}: {:?} (answer {body})",
            String::from_utf8_lossy(&sent)
        );
    }
    let lines = caller_counts(&s);
    assert_eq!(lines.len(), 2, "one more line, the list's: {lines:?}");
    assert_eq!(
        counted(&lines[1], surface("bytes_class")),
        0,
        "a record-served answer ledgers no byte: {lines:?}"
    );
}

/// An agent's final gRPC error status remains its answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_grpc_agents_error_status_is_relayed_as_the_error_it_binds_and_never_trips_it() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-grpc-status";
    let mut agent = GrpcAgent::ending(Vec::new(), "5").await;
    let s = served(instance, &agent.entry("planner"), false, None);
    approve(&s, "planner").await;
    let params = r#"{"message":{"messageId":"m-1","role":"ROLE_USER","parts":[{"text":"PLAN THE MIGRATION"}]}}"#;
    for call in 0..6 {
        let (_, body) = answered(
            &s.router,
            rpc("planner", "SendMessage", params, Some(&s.token)),
        )
        .await;
        assert!(
            !body.contains("breaker_open"),
            "call {call}: NOT_FOUND is no fault of the agent's: {body}"
        );
        let doc: serde_json::Value = serde_json::from_str(&body)
            .unwrap_or_else(|_| panic!("call {call}: an answer: {body}"));
        assert_eq!(
            doc["error"]["code"], -32001,
            "call {call}: NOT_FOUND is TaskNotFound: {body}"
        );
        let mut dials = 0;
        while agent.heard.try_recv().is_ok() {
            dials += 1;
        }
        assert_eq!(
            dials, 1,
            "call {call}: dialled once, never failed over: {body}"
        );
    }
}

/// The far agent's own id for the task the port cells open.
const FAR_TASK: &str = "far-task";

/// An agent's answer to `request` (its whole text) for the port cells: a send is answered
/// with its own task in `send_state`, busbar's registration with that registration, and a
/// `ListTasks` with its own task in `listed_state`.
fn far_answer(request: &str, send_state: &str, listed_state: &str) -> String {
    let originated = |result: serde_json::Value| {
        serde_json::json!({ "jsonrpc": "2.0", "id": "busbar-originated", "result": result })
            .to_string()
    };
    let envelope: serde_json::Value = serde_json::from_str(
        request
            .split_once("\r\n\r\n")
            .expect("an HTTP request body")
            .1,
    )
    .expect("a JSON-RPC request");
    // `card` advertises the legacy interface: its originated registration uses v0.3.
    if envelope["method"] == "tasks/pushNotificationConfig/set" {
        assert_eq!(envelope["params"]["taskId"], FAR_TASK);
        let config = envelope["params"]["pushNotificationConfig"]
            .as_object()
            .expect("v0.3 nests the registered config");
        return serde_json::json!({
            "jsonrpc": "2.0", "id": envelope["id"], "result": {
                "taskId": FAR_TASK, "pushNotificationConfig": config,
            }
        })
        .to_string();
    }
    if request.contains("\"ListTasks\"") {
        return originated(serde_json::json!({ "tasks": [
            { "id": FAR_TASK, "status": { "state": listed_state } }
        ] }));
    }
    serde_json::json!({ "jsonrpc": "2.0", "id": 1, "result": {
        "kind": "task", "id": FAR_TASK, "contextId": "far-context",
        "status": { "state": send_state }
    } })
    .to_string()
}

/// Open one task on `planner` with the cells' `message/send`: busbar's id for it.
async fn open_task(s: &Served) -> String {
    let (status, body) = answered(
        &s.router,
        rpc("planner", "message/send", SEND, Some(&s.token)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the submission is served: {body}");
    let doc: serde_json::Value = serde_json::from_str(&body).expect("an answer");
    let id = doc["result"]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("the submission answered no task id: {body}"))
        .to_string();
    assert_ne!(id, FAR_TASK, "busbar's own id: {body}");
    id
}

/// The caller's own registration of its webhook on `task`.
fn create_config(task: &str) -> String {
    serde_json::json!({
        "taskId": task, "id": "caller-config", "url": "https://1.1.1.1/hook",
        "authentication": { "scheme": "Bearer", "credentials": "caller-secret" },
    })
    .to_string()
}

/// Every request the agent was sent since last asked, whole.
fn heard(agent: &mut Agent) -> Vec<String> {
    let mut heard = Vec::new();
    while let Ok(request) = agent.heard.try_recv() {
        heard.push(request);
    }
    heard
}

/// The exact v0.3 registration sent to the legacy card's backend, including its own capability.
fn v03_callback_token(requests: &[String], backend_task: &str) -> String {
    let mut creates = requests.iter().filter_map(|request| {
        let (_, body) = request.split_once("\r\n\r\n")?;
        let doc: serde_json::Value = serde_json::from_str(body).ok()?;
        (doc["method"] == "tasks/pushNotificationConfig/set").then_some(doc)
    });
    let doc = creates
        .next()
        .expect("a v0.3 callback registration reached the agent");
    assert!(
        creates.next().is_none(),
        "one callback registration per create"
    );
    let token = doc["params"]["pushNotificationConfig"]["authentication"]["credentials"]
        .as_str()
        .filter(|token| !token.is_empty())
        .expect("the nested v0.3 registration carried a capability")
        .to_string();
    assert_eq!(
        doc,
        serde_json::json!({
            "jsonrpc": "2.0", "id": "busbar-originated",
            "method": "tasks/pushNotificationConfig/set", "params": {
                "taskId": backend_task, "pushNotificationConfig": {
                    "id": format!("busbar-{backend_task}"),
                    "url": format!("https://gw.example{}", surface("push_path")),
                    "authentication": {"schemes": ["Bearer"], "credentials": token},
                }
            }
        }),
        "the backend sees the selected v0.3 wire and busbar's own callback"
    );
    token
}

/// The capability registered for the port cells' one backend task.
fn token_sent(requests: &[String]) -> String {
    v03_callback_token(requests, FAR_TASK)
}

/// An agent's report that its task is now `state`, to busbar's own callback, bearing `token`.
fn push(token: &str, state: &str) -> axum::http::Request<axum::body::Body> {
    axum::http::Request::builder()
        .method("POST")
        .uri(surface("push_path"))
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(axum::body::Body::from(
            serde_json::json!({ "id": FAR_TASK, "kind": "task", "status": { "state": state } })
                .to_string(),
        ))
        .expect("a request")
}

/// One task's ending pushed by the agent and delivered by busbar to the caller's own https webhook
/// `hook` (loopback, allow-listed), over the deployment `s` serves: what the webhook heard within
/// `wait`, or `None`.
async fn delivered_within(
    s: &Served,
    agent: &mut Agent,
    hook: &mut Agent,
    wait: std::time::Duration,
) -> Option<String> {
    approve(s, "planner").await;
    let task = open_task(s).await;
    let config = serde_json::json!({
        "taskId": task, "id": "caller-config",
        "url": format!("https://127.0.0.1:{}/hook", hook.port),
        "authentication": { "scheme": "Bearer", "credentials": "caller-secret" },
    })
    .to_string();
    let (status, body) = answered(
        &s.router,
        rpc(
            "planner",
            "CreateTaskPushNotificationConfig",
            &config,
            Some(&s.token),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the callback is registered: {body}");
    let token = token_sent(&heard(agent));
    let (status, body) = answered(&s.router, push(&token, "completed")).await;
    assert_eq!(status, StatusCode::ACCEPTED, "the push is taken: {body}");
    tokio::time::timeout(wait, hook.heard.recv())
        .await
        .ok()
        .flatten()
}

/// **THE OPERATOR'S `agent_push.ca` IS WHAT A DELIVERY TRUSTS ON TOP OF THE PUBLIC ROOTS**
/// (ARCHITECT ruling 2026-10-14): a caller's webhook under a CA the deployment writes there is
/// delivered to.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_delivery_to_a_webhook_under_the_operators_agent_push_ca_is_made() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-push-ca";
    let tls = AgentTls::new();
    tls.rekey();
    let mut hook = Agent::start_over(200, "{}", Some(tls.acceptor())).await;
    let mut agent =
        Agent::start_answering(200, Arc::new(|r: &str| far_answer(r, "working", "working"))).await;
    let s = served_push_trusting(
        instance,
        &agent.entry("planner", "1h"),
        vec!["127.0.0.1".to_string()],
        Some(pem_of(&tls.root)),
    );
    let delivered = delivered_within(&s, &mut agent, &mut hook, std::time::Duration::from_secs(2))
        .await
        .expect("a webhook under the operator's CA is delivered to");
    assert!(delivered.starts_with("POST /hook"), "{delivered}");
}

/// **A WEBHOOK UNDER A CA THE OPERATOR DID NOT WRITE IS REFUSED**: `agent_push.ca` names another
/// CA, so the webhook's chain is to neither it nor the public roots and no delivery reaches it,
/// however many attempts the retry makes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_delivery_to_a_webhook_under_another_ca_is_refused() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-push-other-ca";
    let tls = AgentTls::new();
    tls.rekey();
    let other = AgentTls::new();
    let mut hook = Agent::start_over(200, "{}", Some(tls.acceptor())).await;
    let mut agent =
        Agent::start_answering(200, Arc::new(|r: &str| far_answer(r, "working", "working"))).await;
    let s = served_push_trusting(
        instance,
        &agent.entry("planner", "1h"),
        vec!["127.0.0.1".to_string()],
        Some(pem_of(&other.root)),
    );
    assert_eq!(
        delivered_within(
            &s,
            &mut agent,
            &mut hook,
            std::time::Duration::from_millis(2500),
        )
        .await,
        None,
        "a webhook whose chain is to no trusted CA hears nothing"
    );
}

/// **NO `agent_push:` SECTION: A DELIVERY TRUSTS THE PUBLIC ROOTS ALONE**, as before the section
/// existed: the section is the operator's to write or not, so its absence refuses nothing at
/// boot, and a webhook under a private CA is not delivered to.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_an_agent_push_section_a_delivery_trusts_the_public_roots_alone() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-push-no-ca";
    let tls = AgentTls::new();
    tls.rekey();
    let mut hook = Agent::start_over(200, "{}", Some(tls.acceptor())).await;
    let mut agent =
        Agent::start_answering(200, Arc::new(|r: &str| far_answer(r, "working", "working"))).await;
    let s = served_push_trusting(
        instance,
        &agent.entry("planner", "1h"),
        vec!["127.0.0.1".to_string()],
        None,
    );
    assert_eq!(
        delivered_within(
            &s,
            &mut agent,
            &mut hook,
            std::time::Duration::from_millis(2500),
        )
        .await,
        None,
        "the public roots alone do not reach a private CA's webhook"
    );
}

/// **AN `agent_push.ca` THAT IS NO TRUST ANCHOR REFUSES THE BOOT**, naming the key: the host
/// declares the push need with what the operator wrote, the connection table refuses it, and the
/// composition stops rather than serving a need every delivery of which would be refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_malformed_agent_push_ca_refuses_the_boot() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-push-bad-ca";
    let agent =
        Agent::start_answering(200, Arc::new(|r: &str| far_answer(r, "working", "working"))).await;
    let section = agent.entry("planner", "1h");
    let runtime = tokio::runtime::Handle::current();
    let composed = std::thread::spawn(move || {
        let _in = runtime.enter();
        let _ = served_push_trusting(
            instance,
            &section,
            vec!["127.0.0.1".to_string()],
            Some(
                "-----BEGIN CERTIFICATE-----\nnot a certificate\n-----END CERTIFICATE-----\n"
                    .to_string(),
            ),
        );
    })
    .join();
    let refusal = match composed {
        Ok(()) => panic!("a malformed agent_push.ca composed"),
        Err(payload) => payload
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_string()))
            .unwrap_or_default(),
    };
    assert!(
        refusal.contains("`agent_push.ca` is not a usable trust anchor"),
        "the boot names the key it refuses: {refusal}"
    );
}

/// **AN APPLY CARRYING A MALFORMED `agent_push.ca` IS REFUSED, AND DELIVERIES KEEP THE PREVIOUS
/// ANCHOR** (ARCHITECT ruling 2026-10-14: boot validity and apply validity are one rule).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_apply_carrying_a_malformed_agent_push_ca_is_refused_and_deliveries_keep_the_anchor() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-push-apply-ca";
    let tls = AgentTls::new();
    tls.rekey();
    let mut hook = Agent::start_over(200, "{}", Some(tls.acceptor())).await;
    let mut agent =
        Agent::start_answering(200, Arc::new(|r: &str| far_answer(r, "working", "working"))).await;
    let s = served_push_trusting(
        instance,
        &agent.entry("planner", "1h"),
        vec!["127.0.0.1".to_string()],
        Some(pem_of(&tls.root)),
    );

    crate::dist_root_install::install();
    let text = format!(
        "store: {{module: memory}}\nproviders: {{}}\nmodels: {{}}\n{}:\n  planner: {{ url: \
         https://planner.example/rpc, pin: {{ mechanism: unpinned }} }}\nagent_push:\n  ca: \
         not a certificate\n",
        surface("section")
    );
    let deploy = busbar_kernel::config::deploy_from_yaml_str(&text).expect("the config parses");
    let cfg = busbar_kernel::config::resolve(&deploy, &Default::default()).expect("resolves");
    let rules = Arc::new(crate::root::door_steps::Rules::default());
    rules.hold_owned_anchors(&[root_facts::PUSH_TRUST_FROM]);
    let built = futures::executor::block_on(busbar_kernel::build_app_from_config(
        cfg,
        busbar_kernel::config::PluginsCfg::default(),
        None,
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        (None, None),
        None,
        &(rules as Arc<dyn busbar_kernel::appbuild::RootRules>),
    ));
    let refusal = match built {
        Ok(_) => panic!("an apply carrying a malformed agent_push.ca was built"),
        Err(e) => e,
    };
    assert!(
        refusal.contains("`agent_push.ca` is not a usable trust anchor"),
        "the apply is refused in the boot's words: {refusal}"
    );

    let delivered = delivered_within(&s, &mut agent, &mut hook, std::time::Duration::from_secs(2))
        .await
        .expect("the previous anchor still delivers");
    assert!(delivered.starts_with("POST /hook"), "{delivered}");
}

/// **A DELIVERY REACHES THE WEBHOOK EXACTLY ONCE** (R-PUSH, coordinator round 2): the queued
/// notification's attempt is carried by `tick` and `drive`, and only one of them sends it; the
/// caller's webhook counts one hit, and none follows within 800 ms.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pushed_state_reaches_the_callers_own_webhook_exactly_once() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-push-once";
    let tls = AgentTls::new();
    tls.rekey();
    let mut hook = Agent::start_over(200, "{}", Some(tls.acceptor())).await;
    let mut agent =
        Agent::start_answering(200, Arc::new(|r: &str| far_answer(r, "working", "working"))).await;
    let s = served_pushing(
        instance,
        &agent.entry("planner", "1h"),
        vec!["127.0.0.1".to_string()],
        tls.root.clone(),
    );
    approve(&s, "planner").await;
    let task = open_task(&s).await;
    let config = serde_json::json!({
        "taskId": task, "id": "caller-config",
        "url": format!("https://127.0.0.1:{}/hook", hook.port),
        "authentication": { "scheme": "Bearer", "credentials": "caller-secret" },
    })
    .to_string();
    let (status, body) = answered(
        &s.router,
        rpc(
            "planner",
            "CreateTaskPushNotificationConfig",
            &config,
            Some(&s.token),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the operator-listed callback: {body}"
    );
    assert!(
        !body.contains("error"),
        "the allow-listed loopback callback is registered: {body}"
    );
    let token = token_sent(&heard(&mut agent));
    let (status, body) = answered(&s.router, push(&token, "completed")).await;
    assert_eq!(status, StatusCode::ACCEPTED, "the push is taken: {body}");
    let delivered = tokio::time::timeout(std::time::Duration::from_secs(10), hook.heard.recv())
        .await
        .expect("busbar made no delivery for a pushed state within a second of the push")
        .expect("the webhook heard");
    assert!(
        delivered.starts_with("POST /hook"),
        "the delivery goes to the caller's own webhook path: {delivered}"
    );
    let head = delivered.to_ascii_lowercase();
    assert!(
        head.contains("authorization: bearer caller-secret"),
        "the caller's own webhook credential is presented at the caller's own webhook: {delivered}"
    );

    let again =
        tokio::time::timeout(std::time::Duration::from_millis(800), hook.heard.recv()).await;
    assert!(
        again.is_err(),
        "the delivery reached the webhook a second time: {again:?}"
    );
}

/// **A TRANSITION BUSBAR LEARNS ON A REFRESH REACHES THE CALLER'S WEBHOOK AT ONCE.** The agent
/// moved the task on out of band; the caller's next list asks the agent and the move's
/// notification is delivered to the caller's registered webhook.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refreshed_transition_reaches_the_callers_own_webhook_at_once() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-refresh-delivery";
    let tls = AgentTls::new();
    tls.rekey();
    let mut hook = Agent::start_over(200, "{}", Some(tls.acceptor())).await;
    let mut agent = Agent::start_answering(
        200,
        Arc::new(|r: &str| far_answer(r, "working", "completed")),
    )
    .await;
    let s = served_pushing(
        instance,
        &agent.entry("planner", "1h"),
        vec!["127.0.0.1".to_string()],
        tls.root.clone(),
    );
    approve(&s, "planner").await;
    let task = open_task(&s).await;
    let config = serde_json::json!({
        "taskId": task, "id": "caller-config",
        "url": format!("https://127.0.0.1:{}/hook", hook.port),
        "authentication": { "scheme": "Bearer", "credentials": "caller-secret" },
    })
    .to_string();
    let (status, body) = answered(
        &s.router,
        rpc(
            "planner",
            "CreateTaskPushNotificationConfig",
            &config,
            Some(&s.token),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the config is registered: {body}");
    let _ = heard(&mut agent);
    let _ = listed_state(&s, &task).await;
    let delivered = tokio::time::timeout(std::time::Duration::from_secs(10), hook.heard.recv())
        .await
        .expect("busbar made no delivery for a refreshed move within a second")
        .expect("the webhook heard");
    assert!(
        delivered.starts_with("POST /hook"),
        "the delivery goes to the caller's own webhook path: {delivered}"
    );
    assert!(
        delivered
            .to_ascii_lowercase()
            .contains("authorization: bearer caller-secret"),
        "the caller's own webhook credential is presented: {delivered}"
    );
}

/// The state the caller's own list shows for `task`.
async fn listed_state(s: &Served, task: &str) -> String {
    let (status, body) = answered(
        &s.router,
        rpc("planner", "tasks/list", "{}", Some(&s.token)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the list is served: {body}");
    let doc: serde_json::Value = serde_json::from_str(&body).expect("an answer");
    doc["result"]["tasks"]
        .as_array()
        .and_then(|tasks| tasks.iter().find(|t| t["id"] == task))
        .and_then(|t| t["status"]["state"].as_str())
        .unwrap_or_else(|| panic!("the caller's own task is not in its own list: {body}"))
        .to_string()
}

/// `the_refreshed_state_reaches_the_callers_own_list` (the engine's client-leg cell): the agent
/// moved the task on out of band, and the caller's next list says so, because busbar asked the
/// agent (`ListTasks`) for the rows it holds there before answering.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_refreshed_state_reaches_the_callers_own_list() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-refresh";
    let mut agent = Agent::start_answering(
        200,
        Arc::new(|r: &str| far_answer(r, "working", "completed")),
    )
    .await;
    let s = served(instance, &agent.entry("planner", "1h"), false, None);
    approve(&s, "planner").await;
    let task = open_task(&s).await;
    let _ = heard(&mut agent);
    let state = listed_state(&s, &task).await;
    assert!(
        heard(&mut agent)
            .iter()
            .any(|r| r.contains("\"ListTasks\"")),
        "busbar asked the agent for the rows it holds there"
    );
    assert!(
        ["completed", "TASK_STATE_COMPLETED"].contains(&state.as_str()),
        "the state the agent reported reaches the caller's list: {state}"
    );
}

/// `a_list_with_no_open_task_of_this_callers_makes_no_hop` (the engine's client-leg cell): a
/// caller with nothing live on the agent asks the agent nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_list_with_no_open_task_of_this_callers_makes_no_hop() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-list-no-hop";
    let mut agent = Agent::start(200, ANSWER).await;
    let s = served(instance, &agent.entry("planner", "1h"), false, None);
    approve(&s, "planner").await;
    let (status, body) = answered(
        &s.router,
        rpc("planner", "tasks/list", "{}", Some(&s.token)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        !agent.relayed(),
        "busbar made a hop for a caller with no open task on the agent"
    );
}

/// `a_terminal_task_is_not_armed_at_the_backend` (the engine's pushback cell): the caller's own
/// registration on a task busbar holds as terminal is still busbar's to accept, and busbar
/// registers nothing with the agent for it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_terminal_task_is_not_armed_at_the_backend() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-terminal-unarmed";
    let mut agent = Agent::start_answering(
        200,
        Arc::new(|r: &str| far_answer(r, "completed", "completed")),
    )
    .await;
    let s = served(instance, &agent.entry("planner", "1h"), false, None);
    approve(&s, "planner").await;
    let task = open_task(&s).await;
    let _ = heard(&mut agent);
    let (status, body) = answered(
        &s.router,
        rpc(
            "planner",
            "CreateTaskPushNotificationConfig",
            &create_config(&task),
            Some(&s.token),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let sent = heard(&mut agent);
    assert!(
        sent.is_empty(),
        "busbar must make NO hop for a task it holds as terminal: {sent:?}"
    );
}

/// `a_token_is_not_spent_by_being_used_while_the_task_is_live` (the engine's pushback cell):
/// busbar's capability for the task, read off the registration it sent the agent, admits every
/// report while the task lives, its ending included.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_token_is_not_spent_by_being_used_while_the_task_is_live() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-token-live";
    let mut agent =
        Agent::start_answering(200, Arc::new(|r: &str| far_answer(r, "working", "working"))).await;
    let s = served(instance, &agent.entry("planner", "1h"), false, None);
    approve(&s, "planner").await;
    let task = open_task(&s).await;
    let (status, body) = answered(
        &s.router,
        rpc(
            "planner",
            "CreateTaskPushNotificationConfig",
            &create_config(&task),
            Some(&s.token),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let token = token_sent(&heard(&mut agent));
    for state in ["input-required", "working", "completed"] {
        let (status, body) = answered(&s.router, push(&token, state)).await;
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "the token was refused for `{state}` on a task that had not ended: {body}"
        );
    }
}

/// `a_token_for_a_task_that_has_ended_authorises_nothing` (the engine's pushback cell): the
/// agent's report of the ending is taken; a replay of it, or a report of another terminal state,
/// is `401`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_token_for_a_task_that_has_ended_authorises_nothing() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-token-ended";
    let mut agent =
        Agent::start_answering(200, Arc::new(|r: &str| far_answer(r, "working", "working"))).await;
    let s = served(instance, &agent.entry("planner", "1h"), false, None);
    approve(&s, "planner").await;
    let task = open_task(&s).await;
    let (status, body) = answered(
        &s.router,
        rpc(
            "planner",
            "CreateTaskPushNotificationConfig",
            &create_config(&task),
            Some(&s.token),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let token = token_sent(&heard(&mut agent));
    let (status, body) = answered(&s.router, push(&token, "completed")).await;
    assert_eq!(status, StatusCode::ACCEPTED, "the ending is taken: {body}");
    for state in ["completed", "failed"] {
        let (status, body) = answered(&s.router, push(&token, state)).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "a token for an ended task authorised a `{state}` report: {body}"
        );
    }
}

/// The status and the whole JSON document `req` is answered with.
async fn document(
    s: &Served,
    req: axum::http::Request<axum::body::Body>,
) -> (StatusCode, serde_json::Value) {
    let (status, body) = answered(&s.router, req).await;
    let doc = serde_json::from_str(&body)
        .unwrap_or_else(|e| panic!("the answer is not one JSON document ({e}): {body}"));
    (status, doc)
}

/// Ported from busbar-a2a a2a/tests/local_tests.rs::a_delete_whose_durable_clear_fails_keeps_the_config_and_returns_the_error
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_delete_whose_durable_clear_fails_keeps_the_config_and_returns_the_error() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-delete-refused";
    let agent =
        Agent::start_answering(200, Arc::new(|r: &str| far_answer(r, "working", "working"))).await;
    let s = served(instance, &agent.entry("planner", "1h"), false, None);
    approve(&s, "planner").await;
    let task = open_task(&s).await;
    let (status, body) = answered(
        &s.router,
        rpc(
            "planner",
            "CreateTaskPushNotificationConfig",
            &create_config(&task),
            Some(&s.token),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the config is registered: {body}");
    let addressed = serde_json::json!({ "taskId": task, "id": "caller-config" }).to_string();

    *s.refuse.lock().expect("unpoisoned") = Some(task.as_bytes().to_vec());
    let (status, doc) = document(
        &s,
        rpc(
            "planner",
            "DeleteTaskPushNotificationConfig",
            &addressed,
            Some(&s.token),
        ),
    )
    .await;
    assert_eq!(
        (status, doc),
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({ "jsonrpc": "2.0", "id": 1, "error": {
                "code": -32603,
                "message": "the push notification config could not be deleted; retry the delete",
            } })
        ),
        "a delete whose durable clear failed answers the engine's internal error, never OK"
    );

    *s.refuse.lock().expect("unpoisoned") = None;
    let (status, doc) = document(
        &s,
        rpc(
            "planner",
            "GetTaskPushNotificationConfig",
            &addressed,
            Some(&s.token),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(
        doc["result"]["url"], "https://1.1.1.1/hook",
        "the config was kept: nothing pretended it was cleared"
    );
    let (status, doc) = document(
        &s,
        rpc(
            "planner",
            "DeleteTaskPushNotificationConfig",
            &addressed,
            Some(&s.token),
        ),
    )
    .await;
    assert_eq!(
        (status, doc),
        (
            StatusCode::OK,
            serde_json::json!({ "jsonrpc": "2.0", "id": 1, "result": {} })
        ),
        "once the durable clear succeeds the delete is acknowledged"
    );
    let (status, doc) = document(
        &s,
        rpc(
            "planner",
            "GetTaskPushNotificationConfig",
            &addressed,
            Some(&s.token),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{doc}");
    assert_eq!(doc["error"]["code"], -32001, "removed everywhere: {doc}");
}

/// A REGISTRATION THE STORE REFUSES is not acknowledged: predev's internal error, `500` with
/// `-32603` "the push notification config could not be recorded", echoing the request id
/// (busbar-a2a `local.rs:592-607`, `rpcerror.rs:296`), and nothing is registered.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_registration_the_store_refuses_answers_the_engines_internal_error() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-create-refused";
    let agent =
        Agent::start_answering(200, Arc::new(|r: &str| far_answer(r, "working", "working"))).await;
    let s = served(instance, &agent.entry("planner", "1h"), false, None);
    approve(&s, "planner").await;
    let task = open_task(&s).await;

    *s.refuse.lock().expect("unpoisoned") = Some(task.as_bytes().to_vec());
    let (status, doc) = document(
        &s,
        rpc(
            "planner",
            "CreateTaskPushNotificationConfig",
            &create_config(&task),
            Some(&s.token),
        ),
    )
    .await;
    assert_eq!(
        (status, doc),
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({ "jsonrpc": "2.0", "id": 1, "error": {
                "code": -32603,
                "message": "the push notification config could not be recorded",
            } })
        ),
    );
    *s.refuse.lock().expect("unpoisoned") = None;
    let addressed = serde_json::json!({ "taskId": task, "id": "caller-config" }).to_string();
    let (status, doc) = document(
        &s,
        rpc(
            "planner",
            "GetTaskPushNotificationConfig",
            &addressed,
            Some(&s.token),
        ),
    )
    .await;
    assert_eq!(
        (status, &doc["error"]["code"]),
        (StatusCode::NOT_FOUND, &serde_json::json!(-32001)),
        "nothing was registered: {doc}"
    );
}

/// A SUBMISSION WHOSE TASK THE STORE REFUSES is answered as predev answered a task it could not
/// record, before any hop: `503` with `-32603` "the task could not be recorded".
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_submission_whose_task_the_store_refuses_answers_the_engines_503() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-submit-refused";
    let mut agent = Agent::start(200, ANSWER).await;
    agent.streams();
    let s = served(instance, &agent.entry("planner", "1h"), false, None);
    approve(&s, "planner").await;
    let _ = heard(&mut agent);

    *s.refuse.lock().expect("unpoisoned") = Some(instance.as_bytes().to_vec());
    for (method, params) in [("message/send", SEND), ("message/stream", STREAM)] {
        let (status, doc) = document(&s, rpc("planner", method, params, Some(&s.token))).await;
        assert_eq!(
            (status, doc),
            (
                StatusCode::SERVICE_UNAVAILABLE,
                serde_json::json!({ "jsonrpc": "2.0", "id": 1, "error": {
                    "code": -32603,
                    "message": "the task could not be recorded",
                } })
            ),
            "{method}"
        );
        let sent = heard(&mut agent);
        assert!(sent.is_empty(), "{method}: the agent was dialled: {sent:?}");
    }
}

/// A store refusal while resuming an interrupted task is retryable: the task stays held and the
/// agent receives nothing until its transition can be recorded.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_resumption_the_store_refuses_is_retryable_and_never_dials_the_agent() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-resume-refused";
    let mut agent = Agent::start_answering(
        200,
        Arc::new(|r: &str| far_answer(r, "input-required", "input-required")),
    )
    .await;
    let s = served(instance, &agent.entry("planner", "1h"), false, None);
    approve(&s, "planner").await;
    let turn = r#"{"message":{"kind":"message","messageId":"m-r","role":"user","contextId":"ctx-resume","parts":[{"kind":"text","text":"plan"}]}}"#;
    let (status, body) = answered(
        &s.router,
        rpc("planner", "message/send", turn, Some(&s.token)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the first turn is served: {body}");
    let doc: serde_json::Value = serde_json::from_str(&body).expect("an answer");
    let task = doc["result"]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("the first turn answered no task id: {body}"))
        .to_string();
    let _ = heard(&mut agent);

    *s.refuse.lock().expect("unpoisoned") = Some(task.as_bytes().to_vec());
    let (status, doc) = document(&s, rpc("planner", "message/send", turn, Some(&s.token))).await;
    assert_eq!(
        (status, doc),
        (
            StatusCode::SERVICE_UNAVAILABLE,
            serde_json::json!({ "jsonrpc": "2.0", "id": 1, "error": {
                "code": -32603,
                "message": "this task cannot be resumed",
            } })
        ),
    );
    let sent = heard(&mut agent);
    assert!(sent.is_empty(), "the agent was dialled: {sent:?}");
    *s.refuse.lock().expect("unpoisoned") = None;
    let (status, doc) = document(&s, rpc("planner", "message/send", turn, Some(&s.token))).await;
    assert_eq!(status, StatusCode::OK, "retry after store recovery: {doc}");
    assert_eq!(doc["result"]["id"], task);
    assert!(
        !heard(&mut agent).is_empty(),
        "the recovered retry reaches the agent"
    );
}

/// Ported from busbar-a2a a2a/tests/serve_tests.rs::an_agent_outside_this_callers_catalogue_appears_nowhere_in_the_extended_card.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_agent_outside_this_callers_catalogue_appears_nowhere_in_the_extended_card() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-extended-outside";
    let mut agent = Agent::start(200, ANSWER).await;
    let section = format!(
        "{}\n{}",
        agent.entry("planner", "1h"),
        agent.entry("scheduler", "1h")
    );
    let s = served(instance, &section, false, None);
    approve(&s, "planner").await;
    let (status, body) = answered(
        &s.router,
        rpc("", "GetExtendedAgentCard", "{}", Some(&s.token)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let doc: serde_json::Value = serde_json::from_str(&body).expect("an answer");
    let ids: Vec<&str> = doc["result"]["skills"]
        .as_array()
        .expect("skills")
        .iter()
        .filter_map(|k| k["id"].as_str())
        .collect();
    assert_eq!(ids, ["planner"], "{body}");
    assert!(body.contains("planner"), "{body}");
    assert!(
        !body.contains("scheduler"),
        "an agent outside this caller's catalogue is named in its extended card: {body}"
    );
    assert!(
        !agent.relayed(),
        "the extended card is busbar's, never relayed"
    );
}

/// Ported from busbar-a2a a2a/tests/serve_tests.rs::a_caller_entitled_to_no_agent_gets_an_empty_extended_card_rather_than_a_refusal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_caller_entitled_to_no_agent_gets_an_empty_extended_card_rather_than_a_refusal() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-extended-empty";
    let mut agent = Agent::start(200, ANSWER).await;
    let s = served(
        instance,
        &agent.entry("planner", "1h"),
        false,
        Some(Vec::new()),
    );
    approve(&s, "planner").await;
    let (status, body) = answered(
        &s.router,
        rpc("", "GetExtendedAgentCard", "{}", Some(&s.token)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let doc: serde_json::Value = serde_json::from_str(&body).expect("an answer");
    assert_eq!(doc["result"]["skills"], serde_json::json!([]), "{body}");
    assert_eq!(doc["result"]["capabilities"]["extendedAgentCard"], true);
    assert!(!body.contains("planner"), "{body}");
    assert!(
        !agent.relayed(),
        "the extended card is busbar's, never relayed"
    );
}

/// Verify `card`'s one signature as an outside caller does: the signing input is
/// `protected.b64url(canonical card minus signatures)`, checked under busbar's published card
/// key (the deployment's signer, derived for the door's signing domain).
fn card_signature_verifies(card: &serde_json::Value) -> Result<String, &'static str> {
    use base64::Engine as _;
    use ed25519_dalek::Verifier as _;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let signer = TokenSigner::from_secret_bytes(&[9u8; 32], DEFAULT_KID);
    let key = ed25519_dalek::SigningKey::from_bytes(
        &signer.derived_subkey_seed(surface("card_signing_domain")),
    )
    .verifying_key();
    let sig = card["signatures"].get(0).ok_or("no signature")?;
    let protected = sig["protected"].as_str().ok_or("no protected header")?;
    let raw: [u8; 64] = b64
        .decode(sig["signature"].as_str().ok_or("no signature value")?)
        .map_err(|_| "signature is not base64url")?
        .try_into()
        .map_err(|_| "signature is not 64 bytes")?;
    let input = format!("{protected}.{}", b64.encode(signing_payload(card)));
    key.verify(
        input.as_bytes(),
        &ed25519_dalek::Signature::from_bytes(&raw),
    )
    .map_err(|_| "signature does not verify")?;
    let header: serde_json::Value =
        serde_json::from_slice(&b64.decode(protected).map_err(|_| "header")?)
            .map_err(|_| "header")?;
    Ok(header["kid"].as_str().unwrap_or_default().to_string())
}

/// Ported from busbar-a2a a2a/tests/sign_tests.rs::the_signature_is_taken_over_the_document_that_is_actually_served.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_signature_is_taken_over_the_document_that_is_actually_served() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-signed-card";
    let agent = Agent::start(200, ANSWER).await;
    let s = served(instance, &agent.entry("planner", "1h"), false, None);
    approve(&s, "planner").await;
    let (status, body) = answered(
        &s.router,
        get(&format!("{}/agents/planner", mount()), Some(&s.token)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let card: serde_json::Value = serde_json::from_str(&body).expect("a card");
    assert!(
        !body.contains(&format!("127.0.0.1:{}", agent.port)),
        "the backend must not appear in the served card at all: {body}"
    );
    assert_eq!(
        card["url"],
        format!("https://gw.example{}/agents/planner", mount()),
        "{body}"
    );
    assert!(card["securitySchemes"].get("busbarA2aInbound").is_some());
    assert_eq!(
        card["signatures"].as_array().map(Vec::len),
        Some(1),
        "the vendor's signature is gone and busbar's is the only one: {body}"
    );
    let kid = card_signature_verifies(&card)
        .unwrap_or_else(|why| panic!("the served card must verify: {why}: {body}"));
    assert!(kid.starts_with("busbar-a2a-card-"), "{kid}");

    let mut tampered = card.clone();
    let name = tampered["name"].as_str().expect("a name").to_string();
    tampered["name"] = serde_json::Value::String(format!("{name}x"));
    assert_eq!(
        card_signature_verifies(&tampered),
        Err("signature does not verify"),
        "the signature covers the document that is served"
    );

    let mut scoped = card.clone();
    scoped["securityRequirements"][0]["schemes"]["busbarA2aInbound"]["list"] =
        serde_json::json!(["admin"]);
    assert_eq!(
        card_signature_verifies(&scoped),
        Err("signature does not verify"),
        "only an empty implicit scope list is omitted; a changed requirement must not verify"
    );
}

/// Exposition from the freshly built Prometheus product over the real kernel recorder.
fn render_metrics(s: &Served) -> String {
    use crate::root::loader::dispatch::kinds::export::Export;
    use busbar_contract::export_calls::ExportCalls as _;
    let path = std::path::PathBuf::from(
        std::env::var_os("BUSBAR_TEST_PROMETHEUS_CDYLIB")
            .expect("BUSBAR_TEST_PROMETHEUS_CDYLIB names the actual built exporter"),
    );
    let statement = rendering_of_library(&path)
        .expect("the actual exporter statement reads")
        .expect("the actual exporter states itself");
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let plugin = load_dropped::<Export>(
        &path,
        &statement,
        Bind {
            instance: "a2a-root-metrics".into(),
            max_inflight_cap: 64,
            sink: Arc::new(NoSink),
            dispatcher: dispatcher.adopter(),
            conns: ConnTable::Host(s.riding.inner.clone()),
        },
    )
    .expect("the actual exporter binds");
    let exporter = crate::root::loader::export_door::ExportInstance::open(
        plugin,
        dispatcher,
        br#"{"buffer_seconds":60}"#,
    )
    .expect("the actual exporter opens");
    let families = busbar_kernel::snapshot::snapshot().expect("the product recorder is installed");
    String::from_utf8(
        exporter
            .scrape(&families)
            .expect("the actual exporter scrapes"),
    )
    .expect("the actual exporter emits UTF-8")
}

/// The exposition lines of `family` whose `pool` label is `pool` and `lane` label is `lane`.
fn series_of(s: &Served, family: &str, pool: &str, lane: &str) -> Vec<String> {
    render_metrics(s)
        .lines()
        .filter(|l| l.starts_with(&format!("{family}{{")))
        .filter(|l| l.contains(&format!("pool=\"{pool}\"")))
        .filter(|l| l.contains(&format!("lane=\"{lane}\"")))
        .map(str::to_string)
        .collect()
}

/// The sum of the values of `lines`.
fn total(lines: &[String]) -> f64 {
    lines
        .iter()
        .filter_map(|l| l.rsplit(' ').next()?.parse::<f64>().ok())
        .sum()
}

/// Ported from busbar-a2a a2a/tests/relay_leg_metrics_tests.rs::a_relayed_task_counts_an_upstream_attempt_naming_the_agent_it_was_issued_to.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_relayed_task_counts_an_upstream_attempt_naming_the_agent_it_was_issued_to() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(60));
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-metered";
    let mut agent = Agent::start(200, ANSWER).await;
    let s = served(instance, &agent.entry("metered", "1h"), false, None);
    approve(&s, "metered").await;
    let family = busbar_kernel::telemetry::UPSTREAM_ATTEMPTS_TOTAL;
    let jsonrpc = surface("binding_document");
    let before = total(&series_of(&s, family, "metered", jsonrpc));
    let (status, body) = answered(
        &s.router,
        rpc("metered", "message/send", SEND, Some(&s.token)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(agent.relayed(), "the unit reached the agent");
    let lines = series_of(&s, family, "metered", jsonrpc);
    assert!(
        !lines.is_empty(),
        "a relayed unit left no `{family}` series naming the agent it was issued to and its \
         binding: {}",
        render_metrics(&s)
    );
    assert!(
        total(&lines) > before,
        "the relayed unit was not counted as an attempt: {lines:?}"
    );
    for line in &lines {
        assert!(
            !line.contains("disposition="),
            "the model plane's series shape is pool and lane alone: {line}"
        );
    }
}

/// Ported from busbar-a2a a2a/tests/relay_leg_metrics_tests.rs::a_backend_that_cannot_be_reached_is_counted_as_a_transient_upstream_failure.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_backend_that_cannot_be_reached_is_counted_as_a_transient_upstream_failure() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(60));
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-unreachable";
    let mut agent = Agent::start(200, ANSWER).await;
    let s = served(instance, &agent.entry("unreached", "1h"), false, None);
    approve(&s, "unreached").await;

    let (status, body) = answered(
        &s.router,
        rpc("unreached", "message/send", SEND, Some(&s.token)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "served while it is up: {body}");
    assert!(agent.relayed(), "the warm call reached the agent");
    agent.go_down();
    let family = busbar_kernel::telemetry::UPSTREAM_FAILURES_TOTAL;
    let jsonrpc = surface("binding_document");
    let before = total(&series_of(&s, family, "unreached", jsonrpc));
    let (status, body) = answered(
        &s.router,
        rpc("unreached", "message/send", SEND, Some(&s.token)),
    )
    .await;
    assert_ne!(
        status,
        StatusCode::OK,
        "a hop that never reached the agent: {body}"
    );
    let lines = series_of(&s, family, "unreached", jsonrpc);
    assert!(
        total(&lines) > before,
        "the backend was unreachable and left no `{family}` count for its lane: {lines:?}"
    );
    assert!(
        lines.iter().any(|l| l.contains(&format!(
            "disposition=\"{}\"",
            busbar_kernel::telemetry::DISPOSITION_TRANSIENT
        ))),
        "the failure carries the model plane's own disposition word: {lines:?}"
    );
}

/// A CLIENT CERTIFICATE for registration `who`, issued by a root of its own: that root's DER
/// (what the registration's peer admits), and the paths of the certificate and key it is
/// written to as PEM files (what the registration's `client_identity:` references).
struct ClientIdentityFiles(std::path::PathBuf);

impl Drop for ClientIdentityFiles {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn client_identity_files(
    instance: &str,
    who: &str,
) -> (Vec<u8>, String, String, ClientIdentityFiles) {
    let ca_key = rcgen::KeyPair::generate().expect("a key");
    let mut ca = rcgen::CertificateParams::new(Vec::new()).expect("params");
    ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let root = ca.self_signed(&ca_key).expect("the root").der().to_vec();
    let issuer = rcgen::Issuer::new(ca, ca_key);
    let key = rcgen::KeyPair::generate().expect("a key");
    let leaf = rcgen::CertificateParams::new(vec!["busbar.example".to_string()])
        .expect("params")
        .signed_by(&key, &issuer)
        .expect("the client leaf");
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let files = loop {
        let seq = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("{instance}-{who}-{}-{seq}", std::process::id()));
        match std::fs::create_dir(&dir) {
            Ok(()) => break ClientIdentityFiles(dir),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => panic!("client identity fixture directory: {e}"),
        }
    };
    let cert_path = files.0.join("cert.pem");
    let key_path = files.0.join("key.pem");
    std::fs::write(&cert_path, leaf.pem()).expect("the certificate file");
    std::fs::write(&key_path, key.serialize_pem()).expect("the key file");
    (
        root,
        cert_path.to_string_lossy().into_owned(),
        key_path.to_string_lossy().into_owned(),
        files,
    )
}

/// The `agents:` entry registering `name` at `agent`'s secure path, pinned at the transport by
/// `mtls` to the far end's key `pin`, presenting the certificate and key in the two PEM files.
fn mutual_entry(agent: &Agent, name: &str, pin: &str, cert: &str, key: &str) -> String {
    format!(
        "{name}: {{url: 'https://127.0.0.1:{}/{name}', allow_private: true, reverify_ttl: \
         '1h', pin: {{mechanism: mtls, key: '{pin}'}}, client_identity: {{cert: {{file: \
         '{cert}'}}, key: {{file: '{key}'}}}}}}",
        agent.port
    )
}

/// Ported from busbar-a2a a2a/tests/transport_mutual_tls_tests.rs::the_verb_layers_probe_fetches_a_mutual_tls_vendors_card_with_that_registrations_certificate.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_verb_layers_probe_fetches_a_mutual_tls_vendors_card_with_that_registrations_certificate(
) {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-door-mtls-probe";
    let tls = AgentTls::new();
    let pin = tls.rekey();
    let (client_root, cert, key, _identity_files) = client_identity_files(instance, "planner");
    let agent = Agent::start_over(200, ANSWER, Some(tls.mutual_acceptor(&client_root))).await;
    let section = format!(
        "{}\n{}",
        mutual_entry(&agent, "planner", &pin, &cert, &key),
        agent.entry_pinned("bare", "cert_spki", &pin)
    );
    let s = served_trusting(instance, &section, false, None, Some(tls.root.clone()));

    let (status, preview) = admin(&s, "/agents/planner/connect", "").await;
    assert_eq!(status, StatusCode::OK, "{preview}");
    assert_eq!(preview["failure"], serde_json::Value::Null, "{preview}");
    assert_eq!(preview["state"], "pending", "{preview}");
    assert_eq!(preview["pin_mechanism"], "mtls", "{preview}");
    assert_eq!(
        preview["fingerprint"],
        agent.fingerprint().as_str(),
        "the card came back whole and sighted: {preview}"
    );

    let (status, bare) = admin(&s, "/agents/bare/connect", "").await;
    assert_eq!(status, StatusCode::OK, "{bare}");
    assert!(
        bare["failure"].is_string(),
        "a registration presenting no certificate is refused by the mutual-TLS peer: {bare}"
    );
    assert_eq!(bare["state"], "error", "{bare}");
}

/// Ported from busbar-a2a a2a/tests/transport_mutual_tls_tests.rs::each_registration_presents_its_own_certificate_and_not_another_registrations.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_registration_presents_its_own_certificate_and_not_another_registrations() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-door-mtls-isolation";
    let tls = AgentTls::new();
    let pin = tls.rekey();
    let (planner_root, planner_cert, planner_key, _planner_files) =
        client_identity_files(instance, "planner");
    let (payments_root, payments_cert, payments_key, _payments_files) =
        client_identity_files(instance, "payments");
    let planner_peer =
        Agent::start_over(200, ANSWER, Some(tls.mutual_acceptor(&planner_root))).await;
    let payments_peer =
        Agent::start_over(200, ANSWER, Some(tls.mutual_acceptor(&payments_root))).await;
    let section = [
        mutual_entry(&planner_peer, "planner", &pin, &planner_cert, &planner_key),
        mutual_entry(
            &payments_peer,
            "payments",
            &pin,
            &payments_cert,
            &payments_key,
        ),
        mutual_entry(
            &planner_peer,
            "stranger",
            &pin,
            &payments_cert,
            &payments_key,
        ),
    ]
    .join("\n");
    let s = served_trusting(instance, &section, false, None, Some(tls.root.clone()));

    for own in ["planner", "payments"] {
        let (status, preview) = admin(&s, &format!("/agents/{own}/connect"), "").await;
        assert_eq!(status, StatusCode::OK, "{preview}");
        assert_eq!(
            preview["failure"],
            serde_json::Value::Null,
            "a registration's own certificate is admitted by its own peer: {preview}"
        );
    }
    let (status, foreign) = admin(&s, "/agents/stranger/connect", "").await;
    assert_eq!(status, StatusCode::OK, "{foreign}");
    assert!(
        foreign["failure"].is_string(),
        "another registration's certificate must not authenticate at this peer: {foreign}"
    );
}

/// What a healthy pool member answers a relayed request: a task it is working on.
const TASK_ANSWER: &str = r#"{"jsonrpc":"2.0","id":1,"result":{"kind":"task","id":"far-task","contextId":"far-ctx","status":{"state":"working"}}}"#;

/// The `agents:` section `entries`, with the pool `planner` of `members` (in that order) handed
/// to it as the root hands a named-definition section its unified pools.
#[allow(clippy::needless_update)]
fn pooled(entries: &str, members: &[&str]) -> String {
    let mut section: serde_yaml::Value = serde_yaml::from_str(entries).expect("a section");
    let pools: BTreeMap<String, busbar_kernel::config::pools::CandidatePoolCfg> = [(
        "planner".to_string(),
        busbar_kernel::config::pools::CandidatePoolCfg {
            members: members.iter().map(|m| (*m).to_string()).collect(),
            repeatable: Vec::new(),
            ..Default::default()
        },
    )]
    .into();
    // This is operator configuration, not the runtime door projection. Normal resolution
    // retains these pools; the production builder adds member-grant metadata at the door.
    section[busbar_contract::section::RESERVED_POOLS_KEY] =
        serde_yaml::to_value(pools).expect("the configured candidate pools write");
    serde_yaml::to_string(&section).expect("the section writes")
}

/// ONE AGENT REGISTERED TWICE, `planner-a` then `planner-b` at its paths `/planner-a` and
/// `/planner-b`, pooled as `planner` in that order, each answered at the status `status_of`
/// makes of it.
async fn twins(status_of: Arc<dyn Fn(&str) -> u16 + Send + Sync>) -> (Agent, String) {
    let agent = Agent::start_replying(
        Arc::new(move |request: &str| {
            let status = status_of(request);
            let body = if (200..300).contains(&status) {
                TASK_ANSWER.to_string()
            } else {
                "denied".to_string()
            };
            FarReply::of(status, body)
        }),
        None,
    )
    .await;
    let entries = format!(
        "{}\n{}",
        agent.entry("planner-a", "1h"),
        agent.entry("planner-b", "1h")
    );
    let section = pooled(&entries, &["planner-a", "planner-b"]);
    (agent, section)
}

/// Whether `request` (a relayed request, whole) went to the registration `member`.
fn to_member(request: &str, member: &str) -> bool {
    request.starts_with(&format!("POST /{member} "))
}

/// Every relayed request the agent was sent since it was last asked, kept on `log`.
fn hear(agent: &mut Agent, log: &mut Vec<String>) {
    while let Ok(request) = agent.heard.try_recv() {
        log.push(request);
    }
}

/// How many of the requests on `log` went to `member`.
fn hits(log: &[String], member: &str) -> usize {
    log.iter().filter(|r| to_member(r, member)).count()
}

/// The pool's primary refuses busbar itself (`401`) and its twin is healthy.
fn primary_refused(request: &str) -> u16 {
    if to_member(request, "planner-a") {
        401
    } else {
        200
    }
}

/// The task id busbar answered `body` under.
fn task_id_of(body: &str) -> String {
    let doc: serde_json::Value = serde_json::from_str(body).expect("an answer");
    doc.pointer("/result/id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_else(|| panic!("the accepted task has busbar's id: {body}"))
        .to_string()
}

/// THE REROUTE BATTERY (predev `reroute_battery`): the first fresh submission addressed to the
/// pool's primary reaches it and fails, tripping it; the next goes to the twin by the walk.
async fn reroute_battery(
    s: &Served,
    heard: &mut dyn FnMut() -> (usize, usize),
    (method, params): (&str, &str),
    first: StatusCode,
) {
    let (s1, b1) = answered(&s.router, rpc("planner-a", method, params, Some(&s.token))).await;
    assert_eq!(
        s1,
        first,
        "the first failure is the hop's: {b1}; trust: {:?}",
        admin_get(s, "/trust").await
    );
    assert_eq!(heard(), (1, 0), "the primary was dialled, the twin not");
    let t0 = std::time::Instant::now();
    let (s2, b2) = answered(&s.router, rpc("planner-a", method, params, Some(&s.token))).await;
    assert!(t0.elapsed() < std::time::Duration::from_secs(5));
    assert_eq!(
        s2,
        StatusCode::OK,
        "the twin serves the rerouted submission: {b2}"
    );
    let doc: serde_json::Value = serde_json::from_str(&b2).expect("an answer");
    assert!(
        doc.get("result").is_some(),
        "a served submission has a result: {b2}"
    );
    let (a, b) = heard();
    assert_eq!(a, 1, "the primary untouched on the second call");
    assert!(b >= 1, "the twin served it");
}

/// THE EQUALITY-CELL INSTRUMENT (`failover-reroute × a2a-client`, predev
/// `a_tripped_pool_primary_reroutes_a_fresh_submission_to_the_twin_and_stays_untouched`),
/// JSON-RPC binding.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tripped_pool_primary_reroutes_a_fresh_submission_to_the_twin_and_stays_untouched() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-pool-reroute";
    let (mut agent, section) = twins(Arc::new(primary_refused)).await;
    let s = served(instance, &section, false, None);
    approve(&s, "planner-a").await;
    approve(&s, "planner-b").await;
    let mut log = Vec::new();
    let mut heard = || {
        hear(&mut agent, &mut log);
        (hits(&log, "planner-a"), hits(&log, "planner-b"))
    };
    reroute_battery(
        &s,
        &mut heard,
        ("message/send", SEND),
        StatusCode::BAD_GATEWAY,
    )
    .await;
}

/// The same battery on the gRPC binding (predev
/// `a_tripped_pool_primary_reroutes_a_fresh_submission_on_the_grpc_binding`): the selection sits
/// above the binding axis.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tripped_pool_primary_reroutes_a_fresh_submission_on_the_grpc_binding() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-pool-reroute-grpc";

    let mut primary = GrpcAgent::serving(Vec::new(), "16", 200, None).await;
    let mut twin = GrpcAgent::serving(grpc_working_answer(), "0", 200, Some(primary.port)).await;
    let entries = format!(
        "{}\n{}",
        primary.entry("planner-a"),
        twin.entry("planner-b")
    );
    let s = served(
        instance,
        &pooled(&entries, &["planner-a", "planner-b"]),
        false,
        None,
    );
    approve(&s, "planner-a").await;
    approve(&s, "planner-b").await;
    let (mut a, mut b) = (0, 0);
    let mut heard = || {
        while primary.heard.try_recv().is_ok() {
            a += 1;
        }
        while twin.heard.try_recv().is_ok() {
            b += 1;
        }
        (a, b)
    };
    let params = r#"{"message":{"messageId":"m-1","role":"ROLE_USER","parts":[{"text":"PLAN THE MIGRATION"}]}}"#;

    reroute_battery(
        &s,
        &mut heard,
        ("SendMessage", params),
        StatusCode::INTERNAL_SERVER_ERROR,
    )
    .await;
}

/// THE PINNING SEMANTICS (predev
/// `an_accepted_task_stays_pinned_to_its_member_and_a_tripped_pin_refuses_the_verb`):
///
/// (a) a task the walk placed on the twin at submission is READ at the twin, though the caller
///     addresses the pool's primary: the task row names its member, and every other member is
///     declined;
/// (b) with the pinned member tripped, the task-scoped verb gets the breaker's refusal naming
///     that member (`503` + `Retry-After`), no other member hears a byte, and the task row is
///     not ended: failover is an admission-time choice, never a migration.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_accepted_task_stays_pinned_to_its_member_and_a_tripped_pin_refuses_the_verb() {
    use std::sync::atomic::{AtomicU16, Ordering};
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-pool-pinned";
    let twin_status = Arc::new(AtomicU16::new(200));
    let status = Arc::clone(&twin_status);
    let (mut agent, section) = twins(Arc::new(move |request: &str| {
        if to_member(request, "planner-a") {
            401
        } else {
            status.load(Ordering::SeqCst)
        }
    }))
    .await;
    let s = served(instance, &section, false, None);
    approve(&s, "planner-a").await;
    approve(&s, "planner-b").await;
    let send = || rpc("planner-a", "message/send", SEND, Some(&s.token));
    let _ = answered(&s.router, send()).await;
    let (status, body) = answered(&s.router, send()).await;
    assert_eq!(status, StatusCode::OK, "accepted at the twin: {body}");
    let task_id = task_id_of(&body);
    let mut log = Vec::new();
    hear(&mut agent, &mut log);
    assert_eq!((hits(&log, "planner-a"), hits(&log, "planner-b")), (1, 1));

    let get = format!(r#"{{"id":"{task_id}"}}"#);
    let (status, body) = answered(
        &s.router,
        rpc("planner-a", "tasks/get", &get, Some(&s.token)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    hear(&mut agent, &mut log);
    assert_eq!(
        hits(&log, "planner-a"),
        1,
        "task-scoped traffic never reaches the member not holding it"
    );
    assert_eq!(
        hits(&log, "planner-b"),
        2,
        "the read went to the member holding the task"
    );

    twin_status.store(503, Ordering::SeqCst);
    let mut tripped = false;
    for _ in 0..32 {
        let (_, body) = answered(
            &s.router,
            rpc("planner-a", "tasks/get", &get, Some(&s.token)),
        )
        .await;
        if body.contains("breaker_open") {
            tripped = true;
            break;
        }
    }
    assert!(
        tripped,
        "the pinned member's cell opened within 32 failing reads"
    );
    hear(&mut agent, &mut log);
    let before = (hits(&log, "planner-a"), hits(&log, "planner-b"));
    assert_eq!(before.0, 1, "no read migrated to the primary");
    let response = {
        use tower::ServiceExt as _;
        s.router
            .clone()
            .oneshot(rpc("planner-a", "tasks/get", &get, Some(&s.token)))
            .await
            .expect("the router answers")
    };
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let retry_after = response
        .headers()
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .expect("the refusal carries Retry-After from the cell's own deadline");
    let body = axum::body::to_bytes(response.into_body(), 1 << 16)
        .await
        .expect("the body");
    let body = String::from_utf8_lossy(&body).into_owned();
    let doc: serde_json::Value = serde_json::from_str(&body).expect("an envelope");
    assert_eq!(
        doc["error"]["message"],
        format!(
            "{}.hop.breaker_open: agent `planner-b` is unavailable: its circuit breaker is \
             open after repeated backend failures; busbar did not dispatch this request. \
             Retry after {retry_after}s",
            surface("plane_key")
        ),
        "the refusal names the member the task is pinned to: {body}"
    );
    hear(&mut agent, &mut log);
    assert_eq!(
        (hits(&log, "planner-a"), hits(&log, "planner-b")),
        before,
        "nothing dispatched, and no migration"
    );

    let (status, listed) = answered(
        &s.router,
        rpc("planner-b", "ListTasks", "{}", Some(&s.token)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{listed}");
    let listed: serde_json::Value = serde_json::from_str(&listed).expect("a listing");
    let row = listed["result"]["tasks"]
        .as_array()
        .and_then(|tasks| tasks.iter().find(|t| t["id"] == task_id.as_str()))
        .unwrap_or_else(|| panic!("the task row survives a refused verb: {listed}"));
    let state = row["status"]["state"]
        .as_str()
        .unwrap_or_default()
        .to_ascii_lowercase();
    assert!(
        !state.contains("rejected") && !state.contains("failed"),
        "the task is not ended: {row}"
    );
}

/// THE PIN RULE (predev
/// `a_member_approved_under_a_different_card_fingerprint_is_refused_never_dispatched`):
/// `planner-b` approved under a DIFFERENT card fingerprint is not interchangeable with the primary.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_member_approved_under_a_different_card_fingerprint_is_refused_never_dispatched() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-pool-pin";
    let mut primary = Agent::start(401, "denied").await;
    let mut twin = Agent::start(200, TASK_ANSWER).await;
    let entries = format!(
        "{}\n{}",
        primary.entry("planner-a", "1h"),
        twin.entry("planner-b", "1h")
    );
    let s = served(
        instance,
        &pooled(&entries, &["planner-a", "planner-b"]),
        false,
        None,
    );
    approve(&s, "planner-a").await;
    approve(&s, "planner-b").await;
    let send = || rpc("planner-a", "message/send", SEND, Some(&s.token));
    let _ = answered(&s.router, send()).await;
    assert!(primary.relayed(), "the primary was tripped");
    let (status, body) = answered(&s.router, send()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    let doc: serde_json::Value = serde_json::from_str(&body).expect("an envelope");
    assert_eq!(
        doc["error"]["message"],
        format!(
            "`planner-b` is not interchangeable with `planner-a` in pool `{}:planner`: their \
             approved fingerprints differ ({} vs {}), so busbar cannot show they are the same \
             deployment and will not move a request between them",
            surface("resource_kind"),
            primary.fingerprint(),
            twin.fingerprint()
        ),
        "the refusal says why: {body}"
    );
    assert!(
        doc["error"]["data"].as_array().is_some_and(|d| d
            .iter()
            .any(|e| e["resourceType"] == surface("task_resource_type"))),
        "the refusal names its task: {body}"
    );
    assert!(
        !twin.relayed(),
        "nothing is dispatched to a member busbar cannot show is the same deployment"
    );
    assert!(!primary.relayed(), "nor to the tripped primary");
}

/// DISPOSITION (`disposition × a2a-client`, predev
/// `a_client_fault_answer_never_penalizes_the_agent`): a true 4xx from the primary is the REQUEST's
/// fault, so the member is never penalized.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_client_fault_answer_never_penalizes_the_agent() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-pool-client-fault";
    let mut agent = Agent::start_replying(
        Arc::new(|request: &str| {
            if to_member(request, "planner-a") {
                FarReply::of(
                    400,
                    r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"invalid params"}}"#.to_string(),
                )
            } else {
                FarReply::of(200, TASK_ANSWER.to_string())
            }
        }),
        None,
    )
    .await;
    let entries = format!(
        "{}\n{}",
        agent.entry("planner-a", "1h"),
        agent.entry("planner-b", "1h")
    );
    let section = pooled(&entries, &["planner-a", "planner-b"]);
    let s = served(instance, &section, false, None);
    approve(&s, "planner-a").await;
    approve(&s, "planner-b").await;
    let mut log = Vec::new();

    for call in 1..=6 {
        let (status, body) = answered(
            &s.router,
            rpc("planner-a", "message/send", SEND, Some(&s.token)),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "the caller fault remains a 400 on call {call}: {body}"
        );
        hear(&mut agent, &mut log);
        assert_eq!(
            hits(&log, "planner-a"),
            call,
            "the primary is still dialled after each client fault: {log:?}"
        );
        assert_eq!(
            hits(&log, "planner-b"),
            0,
            "no client fault triggers failover: {log:?}"
        );
    }
    assert_eq!(
        hits(&log, "planner-a"),
        6,
        "an unpenalized member keeps receiving its own traffic"
    );
    assert_eq!(hits(&log, "planner-b"), 0);
}

/// A HOP PINNED TO A POOL MEMBER THE CALLER MAY NO LONGER REACH KEEPS NO FEE (predev
/// `billed_bytes_tests::a_hop_pinned_to_a_member_the_caller_may_not_reach_keeps_no_fee`,
/// A2A-3, Q35).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_hop_pinned_to_a_member_the_caller_may_not_reach_keeps_no_fee() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-pool-pinned-fee";
    let (mut agent, section) = twins(Arc::new(primary_refused)).await;
    let s = served(instance, &section, false, None);
    approve(&s, "planner-a").await;
    approve(&s, "planner-b").await;
    let send = || rpc("planner-a", "message/send", SEND, Some(&s.token));
    let (s1, b1) = answered(&s.router, send()).await;
    assert_eq!(
        s1,
        StatusCode::BAD_GATEWAY,
        "the control hop reaches the dying primary: {b1}"
    );
    let (s2, b2) = answered(&s.router, send()).await;
    assert_eq!(
        s2,
        StatusCode::OK,
        "the twin accepts the placed submission: {b2}"
    );
    let task_id = task_id_of(&b2);

    let mut row = futures::executor::block_on(
        s.gov
            .core_store()
            .expect("native identity owner")
            .identity()
            .get_key(&s.key.id),
    )
    .expect("a read")
    .expect("the key's row");
    row.allowed_scopes = Some(vec![agent_scope("planner-a")]);
    futures::executor::block_on(
        s.gov
            .core_store()
            .expect("native identity owner")
            .identity()
            .put_key(&row),
    )
    .expect("the grant is written");
    futures::executor::block_on(s.gov.refresh_async()).expect("the book reloads");

    let mut log = Vec::new();
    hear(&mut agent, &mut log);
    let sent = log.len();
    let get = format!(r#"{{"id":"{task_id}"}}"#);
    let (s3, b3) = answered(
        &s.router,
        rpc("planner-a", "tasks/get", &get, Some(&s.token)),
    )
    .await;
    assert_eq!(
        s3,
        StatusCode::FORBIDDEN,
        "refused at the egress gate for the twin: {b3}"
    );
    let doc: serde_json::Value = serde_json::from_str(&b3).expect("an envelope");
    assert_eq!(doc["error"]["code"], -32004, "{b3}");
    assert_eq!(
        doc["error"]["message"],
        format!(
            "this key holds no `{}:planner-b` grant, so NO outbound credential is selected for \
             it: busbar does not spend its own credential on behalf of a caller that is not \
             itself authorised for the backend agent",
            surface("scope_kind")
        ),
        "{b3}"
    );
    hear(&mut agent, &mut log);
    assert_eq!(log.len(), sent, "no member saw the refused hop");

    let fees: u64 = caller_counts(&s)
        .iter()
        .map(|c| u64::from(c.fee_count))
        .sum();
    assert_eq!(
        fees, 2,
        "the two hops that left keep their fees; the hop refused for the twin before the \
         socket keeps none"
    );
}

/// THE GRANT ON THE ADDRESSED MEMBER (QP2, coordinator 2026-10-07; predev's admission judged
/// it, `receive.rs:235`, before the charge at `:1543`): a caller granted the twin alone, addressing
/// the pool's primary, is refused for its grant on the primary.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pooled_member_outside_the_callers_grant_is_refused_before_anything_is_charged() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-pool-ungranted";
    let (mut agent, section) = twins(Arc::new(|_: &str| 200)).await;
    let s = served(instance, &section, false, None);
    approve(&s, "planner-a").await;
    approve(&s, "planner-b").await;
    let (key, token) = another_caller(&s, "twin-only", Some(vec![agent_scope("planner-b")]));
    let (status, body) = answered(
        &s.router,
        rpc("planner-a", "message/send", SEND, Some(&token)),
    )
    .await;
    assert_not_granted(status, &body, "planner-a");
    assert!(!agent.relayed(), "nothing was dialled");
    let usage = futures::executor::block_on(s.gov.usage_for_async(
        &s.app.cost,
        &key.id,
        busbar_kernel::store::now(),
    ))
    .expect("a read")
    .expect("the key exists");
    assert_eq!(usage.requests, 0, "nothing charged");
}

/// RESUME AT THE HOLDER (predev `receive.rs:1858-1868`): ANY member's interrupted task under
/// the caller's `contextId` resumes, AT the member that holds it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_interrupted_task_on_any_member_resumes_at_the_member_holding_it() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-pool-resume";
    let mut agent = Agent::start_answering(
        200,
        Arc::new(|_: &str| {
            r#"{"jsonrpc":"2.0","id":1,"result":{"kind":"task","id":"far-b","contextId":"ctx-pool","status":{"state":"input-required"}}}"#
                .to_string()
        }),
    )
    .await;
    let entries = format!(
        "{}\n{}",
        agent.entry("planner-a", "1h"),
        agent.entry("planner-b", "1h")
    );
    let s = served(
        instance,
        &pooled(&entries, &["planner-a", "planner-b"]),
        false,
        None,
    );
    approve(&s, "planner-a").await;
    approve(&s, "planner-b").await;
    let (key, token) = another_caller(&s, "resumer", Some(vec![agent_scope("planner-b")]));
    let message = r#"{"message":{"kind":"message","messageId":"m-r","role":"user","contextId":"ctx-pool","parts":[{"kind":"text","text":"plan"}]}}"#;
    let (status, body) = answered(
        &s.router,
        rpc("planner-b", "message/send", message, Some(&token)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "placed on the twin: {body}");
    let task_id = task_id_of(&body);
    let mut log = Vec::new();
    hear(&mut agent, &mut log);
    assert_eq!((hits(&log, "planner-a"), hits(&log, "planner-b")), (0, 1));

    let mut row = futures::executor::block_on(
        s.gov
            .core_store()
            .expect("native identity owner")
            .identity()
            .get_key(&key.id),
    )
    .expect("a read")
    .expect("the key's row");
    row.allowed_scopes = Some(vec![agent_scope("planner-a"), agent_scope("planner-b")]);
    futures::executor::block_on(
        s.gov
            .core_store()
            .expect("native identity owner")
            .identity()
            .put_key(&row),
    )
    .expect("the grant is written");
    futures::executor::block_on(s.gov.refresh_async()).expect("the book reloads");

    let (status, body) = answered(
        &s.router,
        rpc("planner-a", "message/send", message, Some(&token)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "resumed: {body}");
    assert_eq!(
        task_id_of(&body),
        task_id,
        "the interrupted task resumed, under its id"
    );
    hear(&mut agent, &mut log);
    assert_eq!(
        (hits(&log, "planner-a"), hits(&log, "planner-b")),
        (0, 2),
        "resumed at the member holding it, never moved to the primary"
    );
}

/// A POOLED AGENT HAS NO ONE CARD (predev `receive.rs:1841-1857`): `GetExtendedAgentCard`
/// addressed to a pool member is refused `400` (`UnsupportedOperation`) in predev's words,
/// after the caller's grant on the agent it addressed, never relayed and nothing charged.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_card_read_addressed_to_a_pooled_agent_is_refused_in_predevs_words() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-pool-card";
    let (mut agent, section) = twins(Arc::new(|_: &str| 200)).await;
    let s = served(instance, &section, false, None);
    approve(&s, "planner-a").await;
    approve(&s, "planner-b").await;
    let (status, body) = answered(
        &s.router,
        rpc("planner-a", "GetExtendedAgentCard", "{}", Some(&s.token)),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let doc: serde_json::Value = serde_json::from_str(&body).expect("an envelope");
    assert_eq!(doc["id"], 1, "{body}");
    assert_eq!(doc["error"]["code"], -32004, "{body}");
    assert_eq!(
        doc["error"]["message"],
        "GetExtendedAgentCard is not defined for a pooled agent: its members may present \
         different cards",
        "{body}"
    );
    assert!(!agent.relayed(), "never relayed to a member");
    assert_eq!(admitted(&s), 0, "nothing charged");
}

/// A TASK THE WALK PLACED ON THE TWIN IS NAMED FOR THE AGENT THE CALLER ADDRESSED (predev
/// `receive.rs`: `format!("a2a-{}-{}", admitted.dispatch.agent_id, ..)`, the admitted agent, not
/// the member the walk chose): the id is client-visible.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_task_placed_on_the_twin_is_named_for_the_agent_addressed() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-pool-task-name";
    let (mut agent, section) = twins(Arc::new(primary_refused)).await;
    let s = served(instance, &section, false, None);
    approve(&s, "planner-a").await;
    approve(&s, "planner-b").await;
    let send = || rpc("planner-a", "message/send", SEND, Some(&s.token));
    let _ = answered(&s.router, send()).await;
    let (status, body) = answered(&s.router, send()).await;
    assert_eq!(status, StatusCode::OK, "placed on the twin: {body}");
    let task_id = task_id_of(&body);
    assert!(
        task_id.starts_with(&format!("{}-planner-a-", surface("task_id_prefix"))),
        "the id names the agent addressed, never the twin: {task_id}"
    );
    let mut log = Vec::new();
    hear(&mut agent, &mut log);
    assert_eq!((hits(&log, "planner-a"), hits(&log, "planner-b")), (1, 1));
    let get = format!(r#"{{"id":"{task_id}"}}"#);
    let (status, body) = answered(
        &s.router,
        rpc("planner-a", "tasks/get", &get, Some(&s.token)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    hear(&mut agent, &mut log);
    assert_eq!(
        (hits(&log, "planner-a"), hits(&log, "planner-b")),
        (1, 2),
        "the row names the member holding the task"
    );
}

/// AN UNADDRESSED UNIT WHOSE ONE AGENT IS A POOL MEMBER IS WALKED OVER THE POOL (predev
/// `receive.rs:1262-1268`: the agent `select` chose converges with the addressed path at `:1839`
/// `pool_of` and `:1916` `select_member`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unaddressed_unit_whose_one_agent_is_pooled_is_walked_over_the_pool() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-pool-unaddressed";
    let (mut agent, section) = twins(Arc::new(|request: &str| {
        if to_member(request, "planner-a") {
            503
        } else {
            200
        }
    }))
    .await;
    let s = served(instance, &section, false, None);
    approve(&s, "planner-a").await;
    approve(&s, "planner-b").await;
    let (_, token) = another_caller(&s, "primary-only", Some(vec![agent_scope("planner-a")]));
    let mut tripped = false;
    for _ in 0..32 {
        let (_, body) = answered(
            &s.router,
            rpc("planner-a", "message/send", SEND, Some(&token)),
        )
        .await;
        if body.contains("breaker_open") {
            tripped = true;
            break;
        }
    }
    assert!(
        tripped,
        "the primary's pool cell opened within 32 failing submissions"
    );
    let mut log = Vec::new();
    hear(&mut agent, &mut log);
    let before = (hits(&log, "planner-a"), hits(&log, "planner-b"));
    assert_eq!(before.1, 0, "the twin is outside the caller's grant");
    let (status, body) = answered(&s.router, rpc("", "message/send", SEND, Some(&token))).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    let doc: serde_json::Value = serde_json::from_str(&body).expect("an envelope");
    let message = doc["error"]["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("agent `planner` is unavailable"),
        "the walk's refusal names the pool: {body}"
    );
    hear(&mut agent, &mut log);
    assert_eq!(
        (hits(&log, "planner-a"), hits(&log, "planner-b")),
        before,
        "nothing dialled"
    );
}

/// The audit rows the kernel's chain holds past `before` for `agent`'s resource.
fn audited(s: &Served, before: u64, agent: &str) -> usize {
    let destination = crate::root::door_steps::plane_lane(surface("plane_key"), agent);
    chain(s)
        .iter()
        .filter(|e| e.seq > before && e.what.destination.as_deref() == Some(destination.as_str()))
        .count()
}

/// AN UNADDRESSED LOCAL VERB IS ANSWERED AT THE ONE AGENT THE CALLER'S GRANT REACHES, never over
/// its pool (COORDINATOR ruling 2026-10-07, `ROUTE_SCOPE_LOCAL`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unaddressed_local_verb_is_answered_at_the_tripped_agent_its_grant_reaches() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-pool-local-tripped";
    let (mut agent, section) = twins(Arc::new(|request: &str| {
        if to_member(request, "planner-a") {
            503
        } else {
            200
        }
    }))
    .await;
    let s = served(instance, &section, false, None);
    approve(&s, "planner-a").await;
    approve(&s, "planner-b").await;
    let (key, token) = another_caller(
        &s,
        "local-tripped",
        Some(vec![agent_scope("planner-a"), agent_scope("planner-b")]),
    );

    let mut placed = None;
    for _ in 0..32 {
        let (status, body) = answered(
            &s.router,
            rpc("planner-a", "message/send", SEND, Some(&token)),
        )
        .await;
        if status == StatusCode::OK {
            placed = Some(task_id_of(&body));
            break;
        }
    }
    let task_id = placed.expect("the twin serves once the primary's cell is open");
    let mut row = futures::executor::block_on(
        s.gov
            .core_store()
            .expect("native identity owner")
            .identity()
            .get_key(&key.id),
    )
    .expect("a read")
    .expect("the key's row");
    row.allowed_scopes = Some(vec![agent_scope("planner-a")]);
    futures::executor::block_on(
        s.gov
            .core_store()
            .expect("native identity owner")
            .identity()
            .put_key(&row),
    )
    .expect("the grant is written");
    futures::executor::block_on(s.gov.refresh_async()).expect("the book reloads");
    let mut log = Vec::new();
    hear(&mut agent, &mut log);
    let before = chain(&s).last().map_or(0, |e| e.seq);

    let (status, body) = answered(&s.router, rpc("", "tasks/list", "{}", Some(&token))).await;
    assert_eq!(status, StatusCode::OK, "answered by busbar itself: {body}");
    let listed: serde_json::Value = serde_json::from_str(&body).expect("a listing");
    assert!(
        listed["result"]["tasks"]
            .as_array()
            .is_some_and(|tasks| tasks.iter().any(|t| t["id"] == task_id.as_str())),
        "busbar's own rows for the caller: {body}"
    );
    let mut heard = Vec::new();
    hear(&mut agent, &mut heard);
    assert_eq!(
        (hits(&heard, "planner-a"), hits(&heard, "planner-b")),
        (0, 0),
        "no refresh reaches the twin, and the tripped primary is not dialled: {heard:?}"
    );
    assert_eq!(
        (
            audited(&s, before, "planner-a"),
            audited(&s, before, "planner-b")
        ),
        (1, 0),
        "audited under the agent the caller's grant reaches; actual durable chain: {:?}",
        chain(&s)
    );
}

/// THE TWIN, the pool's primary HEALTHY: a caller granted the twin alone lists its tasks
/// unaddressed and is answered at the twin, the one agent its grant reaches, audited under the
/// twin (the same ruling and predev lines).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unaddressed_local_verb_never_walks_to_a_healthy_primary_outside_the_grant() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-pool-local-healthy";
    let (mut agent, section) = twins(Arc::new(|_: &str| 200)).await;
    let s = served(instance, &section, false, None);
    approve(&s, "planner-a").await;
    approve(&s, "planner-b").await;
    let (_, token) = another_caller(&s, "local-healthy", Some(vec![agent_scope("planner-b")]));
    let mut log = Vec::new();
    hear(&mut agent, &mut log);
    let before = chain(&s).last().map_or(0, |e| e.seq);
    let fetched = agent.fetches();

    let (status, body) = answered(&s.router, rpc("", "tasks/list", "{}", Some(&token))).await;
    assert_eq!(status, StatusCode::OK, "answered by busbar itself: {body}");
    let mut heard = Vec::new();
    hear(&mut agent, &mut heard);
    assert_eq!(
        (hits(&heard, "planner-a"), hits(&heard, "planner-b")),
        (0, 0),
        "neither member was sent a request: {heard:?}"
    );
    assert!(heard.is_empty(), "no egress at all: {heard:?}");
    assert_eq!(agent.fetches(), fetched, "no card was fetched either");
    assert_eq!(
        (
            audited(&s, before, "planner-a"),
            audited(&s, before, "planner-b")
        ),
        (0, 1),
        "audited under the twin, the one agent the caller's grant reaches; actual durable chain: {:?}",
        chain(&s)
    );
}

/// MONEY: AN UNADDRESSED LOCAL VERB BILLS WHAT PREDEV BILLED (`ROUTE_SCOPE_LOCAL` counted,
/// COORDINATOR ruling 2026-10-07).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unaddressed_local_verb_bills_what_predev_billed_on_the_agents_own_line() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-local-billed";
    let mut agent = Agent::start(200, ANSWER).await;
    let priced = Priced {
        bytes_rate: None,
        fee: 2,
        budget: 1_000,
    };
    let s = served_priced(instance, &agent.entry("planner", "1h"), &priced);
    approve(&s, "planner").await;
    let billed = |target: &'static str| {
        let s = &s;
        async move {
            let before = (Billed::of(s), caller_counts(s).len());
            let (status, body) =
                answered(&s.router, rpc(target, "tasks/list", "{}", Some(&s.token))).await;
            assert_eq!(status, StatusCode::OK, "[{target}] answered: {body}");
            let after = Billed::of(s);
            let lines = caller_counts(s);
            assert_eq!(
                lines.len(),
                before.1 + 1,
                "[{target}] one line on the agent's own lane: {lines:?}"
            );
            let line = lines.last().cloned().expect("the line");
            (
                after.requests - before.0.requests,
                after.fees - before.0.fees,
                after.bytes - before.0.bytes,
                after.spend - before.0.spend,
                line.fee_count,
                counted(&line, surface("bytes_class")),
            )
        }
    };
    let addressed = billed("planner").await;
    let unaddressed = billed("").await;
    assert_eq!(
        addressed,
        (1, 1, 0, 2, 1, 0),
        "the addressed list: one request, one fee unit at 2, no bytes (predev's control)"
    );
    assert_eq!(
        unaddressed, addressed,
        "the unaddressed list bills exactly what the addressed one does, on the same line"
    );
    assert!(!agent.relayed(), "neither list dialled the agent");
}

/// A CONFIG APPLY KEEPS THE POOL (`DoorApply::apply`): the generation an apply installs holds
/// the section as written (no pools) and the unified pools beside it; the door is refreshed
/// onto the section carrying them, as boot composes it, so the pool still walks: the primary
/// trips and the next submission is served by the twin.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_config_apply_keeps_the_pool_walking() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-pool-apply";
    let (mut agent, section) = twins(Arc::new(primary_refused)).await;
    let s = served(instance, &section, false, None);
    approve(&s, "planner-a").await;
    approve(&s, "planner-b").await;

    let mut written: serde_yaml::Value = serde_yaml::from_str(&section).expect("a section");
    if let Some(map) = written.as_mapping_mut() {
        map.remove(busbar_contract::section::RESERVED_POOLS_KEY);
    }

    let next = s.applied(written, true);
    s.handle.swap(next).await;
    let mut log = Vec::new();
    let mut heard = || {
        hear(&mut agent, &mut log);
        (hits(&log, "planner-a"), hits(&log, "planner-b"))
    };
    reroute_battery(
        &s,
        &mut heard,
        ("message/send", SEND),
        StatusCode::BAD_GATEWAY,
    )
    .await;
}

/// THE PINNED REFUSAL ANSWERS THE PINNED MEMBER'S OWN WAIT (predev `relay.rs:1659`: the pinned
/// hop's breaker refusal reads `breaker_retry_after_secs` of the pinned member's cell), never the
/// soonest wait across the pool.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pinned_refusal_answers_the_pinned_members_own_wait() {
    use std::sync::atomic::{AtomicU16, AtomicUsize, Ordering};
    let _one = PUBLISHING.lock().await;
    let instance = "serve-agent-door-pool-pinned-wait";
    let twin_status = Arc::new(AtomicU16::new(200));
    let primary_calls = Arc::new(AtomicUsize::new(0));
    let (twin, calls) = (Arc::clone(&twin_status), Arc::clone(&primary_calls));
    let (mut agent, section) = twins(Arc::new(move |request: &str| {
        if to_member(request, "planner-a") {
            if calls.fetch_add(1, Ordering::SeqCst) % 2 == 0 {
                503
            } else {
                200
            }
        } else {
            twin.load(Ordering::SeqCst)
        }
    }))
    .await;
    let s = served(instance, &section, false, None);
    approve(&s, "planner-a").await;
    approve(&s, "planner-b").await;

    let (key, token) = another_caller(&s, "pinned-wait", Some(vec![agent_scope("planner-b")]));
    let (status, body) = answered(
        &s.router,
        rpc("planner-b", "message/send", SEND, Some(&token)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "placed on the twin: {body}");
    let task_id = task_id_of(&body);
    let mut row = futures::executor::block_on(
        s.gov
            .core_store()
            .expect("native identity owner")
            .identity()
            .get_key(&key.id),
    )
    .expect("a read")
    .expect("the key's row");
    row.allowed_scopes = Some(vec![agent_scope("planner-a"), agent_scope("planner-b")]);
    futures::executor::block_on(
        s.gov
            .core_store()
            .expect("native identity owner")
            .identity()
            .put_key(&row),
    )
    .expect("the grant is written");
    futures::executor::block_on(s.gov.refresh_async()).expect("the book reloads");

    twin_status.store(503, Ordering::SeqCst);
    let get = format!(r#"{{"id":"{task_id}"}}"#);
    let mut tripped = false;
    for _ in 0..32 {
        let (_, body) =
            answered(&s.router, rpc("planner-b", "tasks/get", &get, Some(&token))).await;
        if body.contains("breaker_open") {
            tripped = true;
            break;
        }
    }
    assert!(tripped, "the twin's cell opened");

    let mut tripped = false;
    for _ in 0..12 {
        let (_, body) = answered(
            &s.router,
            rpc("planner-a", "message/send", SEND, Some(&token)),
        )
        .await;
        if body.contains("breaker_open") {
            tripped = true;
            break;
        }
    }
    assert!(tripped, "the primary's cell opened");
    assert_eq!(
        primary_calls.load(Ordering::SeqCst),
        5,
        "the primary supplied exactly F/S/F/S/F before opening"
    );
    hear(&mut agent, &mut Vec::new());

    let response = {
        use tower::ServiceExt as _;
        s.router
            .clone()
            .oneshot(rpc("planner-a", "tasks/get", &get, Some(&token)))
            .await
            .expect("the router answers")
    };
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let wait: u64 = response
        .headers()
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .expect("a whole-seconds Retry-After");
    let body = axum::body::to_bytes(response.into_body(), 1 << 16)
        .await
        .expect("the body");
    let body = String::from_utf8_lossy(&body).into_owned();
    assert!(
        body.contains("agent `planner-b` is unavailable")
            && body.contains(&format!("Retry after {wait}s")),
        "the refusal names the member the task is pinned to, with its wait: {body}"
    );
    assert!(
        wait > 60,
        "the twin's own wait (streak 5, near 120 s), never the primary's sooner one (streak 1, \
         near 30 s): {wait}"
    );
    let mut log = Vec::new();
    hear(&mut agent, &mut log);
    assert!(log.is_empty(), "nothing dialled: {log:?}");
}

mod reported_fixture_tests;

mod reported_push_params_tests;

mod relay_reported_cases;
