// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE A2A PLANE'S DOOR, its declarations: what the plane states once in its Statement tail, what

use busbar_contract::abi::host::conn::connector::{
    Need, DIRECTION_OUTBOUND, EGRESS_OPEN_WEB, EGRESS_PROVIDER, KEEP_NAMED,
};
use busbar_contract::abi::mechanism::call::{AbiStr, Blob};
use busbar_contract::abi::mechanism::door::{Section, SECTION_DECLARING};
use busbar_contract::abi::plane::{
    AdminRoute, BillableClass, OpClass, PinMechanism, PlaneTail, RecordChain, RecordRetention,
    TrustKey, ANSWER_LAYOUT, CHAIN_DIGESTS_SCOPE, CHAIN_LENGTH_PREFIXED, INGRESS_REQUEST_RESPONSE,
    INGRESS_RESPONSE_STREAM, MECHANISM_PEER_KEY, MECHANISM_ROOT, PIN_FINGERPRINT, SHAPE_PIECEWISE,
    TAIL_HOOKS_GATED, TAIL_REFUSED_PIECE, TRUST_PIN, TRUST_PRIVATE_REACH, TRUST_RECOVERY_BACKOFF,
    TRUST_REVERIFY_TTL,
};
use busbar_contract::abi::sdk::door::abi_str;
use busbar_contract::abi::sdk::publish::{
    admin_route, record_retention, AdminRouteSpec, ClaimSpec, ServedRoute, SnapshotSpec,
};
use busbar_contract::records::Retention;

use crate::a2a::config::{
    AgentsCfg, DEFAULT_REVERIFY_TTL, REFUSE_PASSTHROUGH_SECTION, SUBJECT_NOUN,
};
use crate::binding::{BINDING_DOCUMENT, BINDING_FRAMED, BINDING_TARGET};
use crate::claims::{DOCUMENT_TRANSPORT, FRAMED_TRANSPORT};

/// The grant kind that admits traffic on this plane: one registered agent.
pub const SCOPE: &str = "agent";
/// The plane's human label.
pub const LABEL: &str = "A2A";
/// The singular noun for one registration in the `agents:` section, in admin responses.
pub const ADMIN_NOUN: &str = "agent";
/// The record resource kind a registration is audited under.
pub const AUDIT_KIND: &str = "a2a_agent";
/// The versioned domain busbar signs the agent cards it serves under.
pub const CARD_SIGNING_DOMAIN: &str = "a2a/agent-card-signing/v1";
/// The `kid` prefix of busbar's card signatures.
pub const CARD_KID_PREFIX: &str = "busbar-a2a-card-";
/// The one billable class a hop's moved bytes are counted in, and its family.
pub const BYTES_FAMILY: &str = "byte";
/// The fee unit this plane declares: one per request.
pub const FEE_PER_REQUEST: &str = busbar_contract::plane::PER_REQUEST;
/// The recovery backoff an entry that spells none gets: fifteen minutes.
pub const DEFAULT_RECOVERY_BACKOFF: &str = "15m";

/// An absent string.
const NONE: AbiStr = AbiStr::ABSENT;

/// The push queue's counters, the Statement's metric families (a per-task ordered bounded queue,

pub const FAMILIES: &[busbar_contract::abi::mechanism::door::MetricFamily] = &[
    counter(
        METRIC_PUSH_DROPPED,
        "A2A push notifications dropped, oldest first, from a full per-task queue",
    ),
    counter(
        METRIC_PUSH_UNFILED,
        "A2A push delivery outcomes dropped unfiled from a full book of owed outcomes",
    ),
];

/// [`FAMILIES`]' name for the push notifications a full queue dropped.
pub const METRIC_PUSH_DROPPED: &str = "busbar_a2a_push_notifications_dropped_total";

/// [`FAMILIES`]' name for the delivery outcomes dropped unfiled.
pub const METRIC_PUSH_UNFILED: &str = "busbar_a2a_push_outcomes_unfiled_total";

/// [`METRIC_PUSH_DROPPED`]'s index in [`FAMILIES`].
pub const FAMILY_PUSH_DROPPED: u32 = 0;

/// [`METRIC_PUSH_UNFILED`]'s index in [`FAMILIES`].
pub const FAMILY_PUSH_UNFILED: u32 = 1;

/// One unlabelled counter family.
const fn counter(
    name: &'static str,
    help: &'static str,
) -> busbar_contract::abi::mechanism::door::MetricFamily {
    busbar_contract::abi::mechanism::door::MetricFamily::new(
        abi_str(name),
        abi_str(help),
        NONE,
        busbar_contract::abi::mechanism::door::FAMILY_COUNTER,
    )
}

/// The plane's settings sections, as its Statement states them: `agents:` is the one it declares;

pub const SECTIONS: &[Section] = &[
    Section {
        name: abi_str(crate::CONFIG_SECTION),
        flags: SECTION_DECLARING,
        ..Section::ZERO
    },
    Section {
        name: abi_str(PUSH_SECTION),
        flags: 0,
        ..Section::ZERO
    },
];

/// THE PLANE'S OWN `agent_push:` SECTION (new in 1.6.0; absent = public roots): `{ca: <PEM>}`, the operator

pub const PUSH_SECTION: &str = "agent_push";

/// The [`PUSH_SECTION`] key holding the operator CA, PEM text.
pub const PUSH_CA_KEY: &str = "ca";

/// WHERE [`NEED_OPEN_WEB`]'s TRUST ANCHOR COMES FROM: [`PUSH_SECTION`]`.`[`PUSH_CA_KEY`] in the

pub const PUSH_TRUST_FROM: &str = "owned.agent_push.ca";

/// Judge the [`PUSH_SECTION`] the plane's owned sections (`{section: value}`, JSON) write: absent

pub fn read_push_section(owned: &[u8]) -> Result<(), String> {
    use serde_json::Value;
    if owned.is_empty() {
        return Ok(());
    }
    let all: Value = serde_json::from_slice(owned).map_err(|e| format!("`{PUSH_SECTION}`: {e}"))?;
    match all.get(PUSH_SECTION) {
        None | Some(Value::Null) => Ok(()),
        Some(Value::Object(fields)) => {
            for (key, value) in fields {
                if key != PUSH_CA_KEY {
                    return Err(format!(
                        "`{PUSH_SECTION}.{key}` is not a key of `{PUSH_SECTION}:`; it holds \
                         `{PUSH_CA_KEY}` alone"
                    ));
                }
                if !value.as_str().is_some_and(|text| !text.trim().is_empty()) {
                    return Err(format!(
                        "`{PUSH_SECTION}.{PUSH_CA_KEY}` must be the operator CA as PEM text"
                    ));
                }
            }
            Ok(())
        }
        Some(_) => Err(format!(
            "`{PUSH_SECTION}:` must be a mapping, `{{{PUSH_CA_KEY}: <PEM>}}`"
        )),
    }
}

/// The three bindings, in the order the wire formats are named.
const DIALECTS: &[AbiStr] = &[
    abi_str(BINDING_DOCUMENT),
    abi_str(BINDING_TARGET),
    abi_str(BINDING_FRAMED),
];

const SCOPE_KINDS: &[AbiStr] = &[abi_str(SCOPE)];

/// [`DIALECTS`] index of the JSON-RPC line's dialect.
pub const DIALECT_DOCUMENT: u32 = 0;
/// [`DIALECTS`] index of the HTTP+JSON line's dialect.
pub const DIALECT_TARGET: u32 = 1;
/// [`DIALECTS`] index of the gRPC line's dialect.
pub const DIALECT_FRAMED: u32 = 2;

const fn op_class(i: usize) -> OpClass {
    OpClass {
        op: abi_str(crate::ops::OP_CLASSES[i].as_str()),
        name: abi_str(crate::ops::OP_CLASSES[i].as_str()),
    }
}

/// The operation classes, in [`crate::ops::OP_CLASSES`] order: `arrive` names one by its index.
const OP_CLASS_TABLE: &[OpClass] = &[
    op_class(0),
    op_class(1),
    op_class(2),
    op_class(3),
    op_class(4),
    op_class(5),
    op_class(6),
    op_class(7),
    op_class(8),
    op_class(9),
    op_class(10),
    op_class(11),
];

const BILLABLE_CLASSES: &[BillableClass] = &[
    BillableClass {
        class: abi_str("bytes"),
        family: abi_str(BYTES_FAMILY),
    },
    BillableClass {
        class: abi_str(FEE_PER_REQUEST),
        family: abi_str(FEE_FAMILY),
    },
];

/// The family of the fee unit's class: a count of 0 or 1.
pub const FEE_FAMILY: &str = "count";

/// The tail index of the bytes class in the billable classes.
pub const CLASS_BYTES_INDEX: u32 = 0;

/// The tail index of the fee unit's class in the billable classes.
pub const CLASS_FEE_INDEX: u32 = 1;

const FEE_UNITS: &[AbiStr] = &[abi_str(FEE_PER_REQUEST)];

/// [`crate::records::HELD_KINDS`] in the ABI's spelling.
const RECORD_KINDS: &[AbiStr] = &[
    abi_str(crate::records::HELD_KINDS[0]),
    abi_str(crate::records::HELD_KINDS[1]),
    abi_str(crate::records::HELD_KINDS[2]),
    abi_str(crate::records::HELD_KINDS[3]),
    abi_str(crate::records::HELD_KINDS[4]),
];

/// The retention rule of each held kind that is not purged by age: a task row is kept while it is

const RECORD_RETENTIONS: &[RecordRetention] = &[record_retention(0, Retention::TerminalOnly)];

/// The task chain: the task-event kind is chained, length-prefixed with its scope in the

const RECORD_CHAINS: &[RecordChain] = &[RecordChain {
    kind: crate::records::TASK_EVENT_INDEX,
    framing: CHAIN_LENGTH_PREFIXED,
    flags: CHAIN_DIGESTS_SCOPE,
    _reserved: 0,
}];

/// The pin's four mechanisms; three are authenticity roots and `unpinned` is not. `cert_spki` and

const PIN_MECHANISMS: &[PinMechanism] = &[
    PinMechanism {
        token: abi_str("jws_issuer_key"),
        flags: MECHANISM_ROOT,
        _reserved: 0,
    },
    PinMechanism {
        token: abi_str("cert_spki"),
        flags: MECHANISM_ROOT | MECHANISM_PEER_KEY,
        _reserved: 0,
    },
    PinMechanism {
        token: abi_str("mtls"),
        flags: MECHANISM_ROOT | MECHANISM_PEER_KEY,
        _reserved: 0,
    },
    PinMechanism {
        token: abi_str("unpinned"),
        flags: 0,
        _reserved: 0,
    },
];

/// The kernel-owned trust keys of one entry (the `pin:` object over this plane's four mechanisms,

const TRUST_KEYS: &[TrustKey] = &[
    trust_key("pin", TRUST_PIN, PIN_FINGERPRINT, NONE).with_mechanisms(PIN_MECHANISMS),
    trust_key(
        "reverify_ttl",
        TRUST_REVERIFY_TTL,
        0,
        abi_str(DEFAULT_REVERIFY_TTL),
    ),
    trust_key(
        "recovery_backoff",
        TRUST_RECOVERY_BACKOFF,
        0,
        abi_str(DEFAULT_RECOVERY_BACKOFF),
    ),
    trust_key(PRIVATE_REACH_KEY, TRUST_PRIVATE_REACH, 0, NONE),
];

/// One trust key's plain fields; its mechanisms (a pin's) are set by the caller.
const fn trust_key(key: &'static str, role: u32, flags: u32, default: AbiStr) -> TrustKey {
    let mut t = TrustKey::EMPTY;
    t.key = abi_str(key);
    t.role = role;
    t.flags = flags;
    t.default = default;
    t
}

/// The per-registration key holding an agent's private reach (`allow_private`).
pub const PRIVATE_REACH_KEY: &str = "allow_private";

/// The [`NEEDS`] index of the plane's own outbound hops to a caller's push callback, each to the

pub const NEED_OPEN_WEB: u32 = 0;

/// The [`NEEDS`] index of the relayed calls to the registered agents: one member route per agent,

pub const NEED_AGENT: u32 = 1;

/// The [`NEEDS`] index of the relayed calls to the registered agents whose card's binding is gRPC

pub const NEED_GRPC: u32 = 2;

/// THE MEMBER-TARGET PATH of [`NEED_AGENT`] (`busbar_contract::section::MEMBER_TARGET_PREFIX`): each

pub const MEMBER_TARGET: &str = "settings.*.url";

/// WHERE [`NEED_AGENT`]'s TRUST ANCHORS COME FROM, beside the agent's pin (Q-DEL-A2A-SPKI): each

pub const CLIENT_IDENTITY_FROM: &str = "settings.*.client_identity";

/// The far end's response fields the plane reads: the answer's media type (a JSON document or an

const KEEP_RESPONSE_HEADERS: &[AbiStr] =
    &[abi_str(crate::relay::H_CONTENT_TYPE), abi_str("location")];

/// The secret references its section holds, by settings path (`*` = every registered agent): the

pub const SECRET_REFS: &[AbiStr] = &[
    abi_str("settings.*.upstream_credential.secret"),
    abi_str("settings.*.client_identity.cert"),
    abi_str("settings.*.client_identity.key"),
];

/// THE PLANE'S CONNECTION NEEDS: its own outbound hops over http under the `open-web` class (public

pub const NEEDS: &[Need] = &[
    need(
        EGRESS_OPEN_WEB,
        DOCUMENT_TRANSPORT,
        NONE,
        abi_str(PUSH_TRUST_FROM),
    ),
    need(
        EGRESS_PROVIDER,
        DOCUMENT_TRANSPORT,
        abi_str(MEMBER_TARGET),
        abi_str(CLIENT_IDENTITY_FROM),
    )
    .with_keep_response_headers(KEEP_RESPONSE_HEADERS),
    need(
        EGRESS_PROVIDER,
        FRAMED_TRANSPORT,
        abi_str(MEMBER_TARGET),
        abi_str(CLIENT_IDENTITY_FROM),
    )
    .with_keep_response_headers(KEEP_RESPONSE_HEADERS),
];

/// One outbound need's plain fields; its response header list is set by the caller.
const fn need(
    egress_class: u32,
    transport: &'static str,
    target_from: AbiStr,
    trust_from: AbiStr,
) -> Need {
    let mut n = Need::EMPTY;
    n.direction = DIRECTION_OUTBOUND;
    n.egress_class = egress_class;
    n.transport = abi_str(transport);
    n.auth = NONE;
    n.target_from = target_from;
    n.trust_from = trust_from;
    n.keep_mode = KEEP_NAMED;
    n
}

/// The Statement tail: the plane's static facts.
pub const TAIL: &PlaneTail = &{
    let mut t = PlaneTail::EMPTY
        .with_dialects(DIALECTS)
        .with_scope_kinds(SCOPE_KINDS)
        .with_op_classes(OP_CLASS_TABLE)
        .with_billable_classes(BILLABLE_CLASSES)
        .with_fee_units(FEE_UNITS)
        .with_record_kinds(RECORD_KINDS)
        .with_record_chains(RECORD_CHAINS)
        .with_trust_keys(TRUST_KEYS)
        .with_admin_routes(ADMIN_ROUTES)
        .with_metric_lanes(DIALECTS);

    t.flags = TAIL_HOOKS_GATED | TAIL_REFUSED_PIECE;
    t.ingress = INGRESS_REQUEST_RESPONSE | INGRESS_RESPONSE_STREAM;
    t.dispatch_shape = SHAPE_PIECEWISE;

    t.answer_layout = ANSWER_LAYOUT;
    t.scope = abi_str(SCOPE);
    t.label = abi_str(LABEL);
    t.subject_noun = abi_str(SUBJECT_NOUN);
    t.admin_noun = abi_str(ADMIN_NOUN);
    t.audit_kind = abi_str(AUDIT_KIND);
    t.signing_domain = abi_str(CARD_SIGNING_DOMAIN);
    t.signing_kid_prefix = abi_str(CARD_KID_PREFIX);
    t.cli_help = NONE;
    t.caller_credential_refusal = abi_str(REFUSE_PASSTHROUGH_SECTION);
    t.admin_openapi = Blob::json(ADMIN_OPENAPI.as_bytes());

    t.record_retentions = RECORD_RETENTIONS.as_ptr();
    t.record_retentions_len = RECORD_RETENTIONS.len();

    t.stream_ceiling_secs = STREAM_CEILING_SECS;
    t
};

/// How long a unit whose answer streams may run (600 s): the plane's stated stream ceiling, which the kernel stamps as the unit's

pub const STREAM_CEILING_SECS: u64 = 600;

/// One path the plane answers on: the SDK's one route row ([`ServedRoute`]): the verb, the target

pub type Route = ServedRoute;

/// The carrier the document and target bindings arrive over.
const CARRIER: &str = DOCUMENT_TRANSPORT;

const fn keyed(verb: &'static str, target: &'static str) -> Route {
    Route {
        verb,
        target,
        carrier: CARRIER,
        open: false,
    }
}

const fn open(verb: &'static str, target: &'static str) -> Route {
    Route {
        verb,
        target,
        carrier: CARRIER,
        open: true,
    }
}

/// ONE FRONTED AGENT'S JSON-RPC ENDPOINT, `POST /a2a/agents/{agent_id}`: a row of [`ROUTES`], and

pub const AGENT_ENDPOINT: Route = keyed("POST", "/a2a/agents/{agent_id}");

/// The plane's data routes, in declaration order: named operations and cards,

pub const ROUTES: &[Route] = &[
    keyed("POST", "/a2a/message:send"),
    keyed("POST", "/a2a/message:stream"),
    keyed("GET", "/a2a/tasks"),
    keyed("GET", "/a2a/tasks/{id}"),
    keyed("POST", "/a2a/tasks/{id}"),
    keyed("POST", "/a2a/tasks/{id}/pushNotificationConfigs"),
    keyed("GET", "/a2a/tasks/{id}/pushNotificationConfigs"),
    keyed("GET", "/a2a/tasks/{id}/pushNotificationConfigs/{config_id}"),
    keyed(
        "DELETE",
        "/a2a/tasks/{id}/pushNotificationConfigs/{config_id}",
    ),
    keyed("GET", "/a2a/extendedAgentCard"),
    open("GET", "/.well-known/oauth-protected-resource/a2a"),
    open("GET", "/.well-known/agent-card.json"),
    keyed("GET", "/a2a/agents/{agent_id}/.well-known/agent-card.json"),
    keyed("GET", "/a2a/agents/{agent_id}"),
    AGENT_ENDPOINT,
    keyed("POST", "/a2a"),
    keyed("POST", "/a2a/"),
    Route {
        verb: "POST",
        target: "/lf.a2a.v1.A2AService/{method}",
        carrier: FRAMED_TRANSPORT,
        open: false,
    },
];

/// Which line of the one A2A dialect a route is (JSON-RPC,
/// REST and gRPC are its lines, each with its own refusal dialect), or a card document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Line {
    /// The JSON-RPC endpoint, in both spellings, and one agent addressed by name.
    Document,
    /// The HTTP+JSON binding's named operations and the authenticated card.
    Target,
    /// The gRPC service.
    Framed,
    /// A discovery document or an agent card/address read. Credential requirements
    /// remain the route's claim flags; this name does not imply an open claim.
    Open,
}

impl Line {
    /// The [`DIALECTS`] index its refusals are rendered in; `None` for a card document, whose

    #[must_use]
    pub const fn dialect(self) -> Option<u32> {
        match self {
            Line::Document => Some(DIALECT_DOCUMENT),
            Line::Target => Some(DIALECT_TARGET),
            Line::Framed => Some(DIALECT_FRAMED),
            Line::Open => None,
        }
    }
}

/// The line `route` is.
#[must_use]
pub fn line_of(route: &Route) -> Line {
    if route.carrier == FRAMED_TRANSPORT {
        return Line::Framed;
    }
    if route.open
        || (route.verb == "GET"
            && matches!(
                route.target,
                "/a2a/agents/{agent_id}" | "/a2a/agents/{agent_id}/.well-known/agent-card.json"
            ))
    {
        return Line::Open;
    }
    if route.verb == "POST" && matches!(route.target, "/a2a" | "/a2a/" | "/a2a/agents/{agent_id}") {
        return Line::Document;
    }
    Line::Target
}

/// The trust verbs the plane serves on the kernel's admin mount, relative to it: `(verb, target)`;

pub const ADMIN_VERBS: &[(&str, &str)] = &[
    ("POST", "/agents/{name}/connect"),
    ("POST", "/agents/{name}/approve"),
    ("POST", "/a2a/push"),
];

/// BUSBAR'S OWN PUSH CALLBACK's index in [`ADMIN_VERBS`]: `POST /a2a/push`, a PUBLIC route

pub const PUSH_ROUTE: usize = 2;

/// The word the kernel's audit row names each [`ADMIN_VERBS`] request by: the audit verbs

pub const ADMIN_AUDIT_VERBS: [&str; 3] = ["connect", "approve", ""];

/// [`ADMIN_VERBS`] in the ABI's spelling, each audited under its [`ADMIN_AUDIT_VERBS`] word.
pub const ADMIN_ROUTES: &[AdminRoute] = &[
    admin_route(ADMIN_VERBS[0], 0, ADMIN_AUDIT_VERBS[0]),
    admin_route(ADMIN_VERBS[1], 0, ADMIN_AUDIT_VERBS[1]),
    admin_route(
        ADMIN_VERBS[PUSH_ROUTE],
        busbar_contract::abi::plane::ROUTE_PUBLIC
            | busbar_contract::abi::plane::ROUTE_CARRIES_OWN_TOKEN,
        ADMIN_AUDIT_VERBS[PUSH_ROUTE],
    ),
];

/// The trust verbs' OpenAPI fragment, each path relative to the admin mount (the kernel keys it

pub const ADMIN_OPENAPI: &str = include_str!("admin_openapi.json");

/// THE TRUST VERBS' OpenAPI FRAGMENT ([`ADMIN_OPENAPI`]), each path keyed under `admin_prefix`

#[must_use]
pub fn openapi_fragment(admin_prefix: &str) -> serde_json::Value {
    let Ok(serde_json::Value::Object(paths)) = serde_json::from_str(ADMIN_OPENAPI) else {
        return serde_json::Value::Object(serde_json::Map::new());
    };
    serde_json::Value::Object(
        paths
            .into_iter()
            .map(|(rel, item)| {
                if rel == "components" {
                    (rel, item)
                } else {
                    (format!("{admin_prefix}{rel}"), item)
                }
            })
            .collect(),
    )
}

/// `validate` and `open`: the settings blob read as the `agents:` section. An empty blob is the

pub fn read_agents_section(settings: &[u8]) -> Result<AgentsCfg, String> {
    if settings.is_empty() {
        return Ok(AgentsCfg::default());
    }

    if let Some((rest, pools)) = lift_pools(settings) {
        let mut cfg = read_section(&rest)?;
        cfg.pools = pools;
        return Ok(cfg);
    }
    read_section(settings)
}

/// Each failover pool's members, by pool name, in the order declared.
type Pools = indexmap::IndexMap<String, Vec<String>>;

/// The section's reserved `pools` key taken off `settings`: the rest of the section (its keys in

fn lift_pools(settings: &[u8]) -> Option<(Vec<u8>, Pools)> {
    use busbar_contract::section::{POOL_MEMBERS_KEY, POOL_MEMBER_NAME_KEY, RESERVED_POOLS_KEY};
    let mut section: indexmap::IndexMap<String, serde_json::Value> =
        serde_json::from_slice(settings).ok()?;
    let stated = section.shift_remove(RESERVED_POOLS_KEY)?;
    let pools: Pools = stated
        .as_object()
        .into_iter()
        .flatten()
        .map(|(name, pool)| {
            let members: Vec<String> = pool
                .get(POOL_MEMBERS_KEY)
                .and_then(serde_json::Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|m| {
                    m.as_str()
                        .or_else(|| {
                            m.get(POOL_MEMBER_NAME_KEY)
                                .and_then(serde_json::Value::as_str)
                        })
                        .map(str::to_string)
                })
                .collect();
            (name.clone(), members)
        })
        .collect();
    Some((serde_json::to_vec(&section).ok()?, pools))
}

/// The section `settings` read, in the grammar's words.
fn read_section(settings: &[u8]) -> Result<AgentsCfg, String> {
    serde_json::from_slice::<AgentsCfg>(settings).map_err(|e| {
        let text = e.to_string();
        let at = format!(" at line {} column {}", e.line(), e.column());
        match text.strip_suffix(&at) {
            Some(sentence) if e.line() > 0 => sentence.to_string(),
            _ => text,
        }
    })
}

/// THE SECTION A DEALT `validate` BLOB CARRIES. The boot's stage-3g deal hands a declared-verb

#[must_use]
pub fn dealt_section(settings: &[u8]) -> std::borrow::Cow<'_, [u8]> {
    match serde_json::from_slice::<serde_json::Map<String, serde_json::Value>>(settings) {
        Ok(map) if map.len() == 1 => match map.get(crate::CONFIG_SECTION) {
            Some(section) => serde_json::to_vec(section).map_or(
                std::borrow::Cow::Borrowed(settings),
                std::borrow::Cow::Owned,
            ),
            None => std::borrow::Cow::Borrowed(settings),
        },
        _ => std::borrow::Cow::Borrowed(settings),
    }
}

/// ONE GENERATION'S SNAPSHOT, owned, for the SDK to publish until that generation's `retire`.

#[must_use]
pub fn agents_snapshot_spec(public_url: Option<&str>, agents: &[&str]) -> SnapshotSpec {
    let fronts = !agents.is_empty();
    let admitted = public_url.filter(|_| fronts).and_then(|p| {
        Some((
            crate::a2a::public::absolute(p, crate::MOUNT_PATH)?,
            crate::a2a::public::absolute(p, crate::METADATA_PATH)?,
        ))
    });
    let (audience, resource_metadata, claims) = match admitted {
        Some((a, m)) => (
            Some(a),
            Some(m),
            ROUTES
                .iter()
                .map(dialect_claim)
                .chain(agent_slash_claims(agents))
                .collect(),
        ),
        None => (None, None, Vec::new()),
    };
    SnapshotSpec {
        claims,

        admin_routes: ADMIN_ROUTES
            .iter()
            .zip(ADMIN_VERBS)
            .zip(ADMIN_AUDIT_VERBS)
            .filter(|((r, _), _)| {
                fronts || r.flags & busbar_contract::abi::plane::ROUTE_PUBLIC == 0
            })
            .map(|((r, (verb, target)), audit)| {
                AdminRouteSpec::new(verb, target, r.flags).audited(audit)
            })
            .collect(),
        openapi: Some(openapi_fragment("").to_string().into_bytes()),
        audience,
        resource_metadata,
        resource_facts: None,
        listed: Vec::new(),
    }
}

/// The trailing-separator spelling of each fronted agent's endpoint: an A2A client joins its relative calls to the card's `url` and so arrives at

#[must_use]
pub fn agent_slash_claims(agents: &[&str]) -> Vec<ClaimSpec> {
    agents
        .iter()
        .filter_map(|agent| agent_slash_target(agent))
        .map(|target| {
            let mut spec = ClaimSpec::new(
                AGENT_ENDPOINT.verb,
                &target,
                AGENT_ENDPOINT.carrier,
                busbar_contract::abi::plane::CLAIM_EXACT,
            );
            spec.refusal_dialect = u16::try_from(DIALECT_DOCUMENT).unwrap_or_default();
            spec
        })
        .collect()
}

/// `/a2a/agents/<agent>/`, or `None` for a name that is not one plain path segment.
#[must_use]
pub fn agent_slash_target(agent: &str) -> Option<String> {
    plain_segment(agent).then(|| format!("{}/agents/{agent}/", crate::MOUNT_PATH))
}

/// Whether `name` is one plain path segment (unreserved characters only, not `.` or `..`).
fn plain_segment(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '~'))
}

/// The route the kernel's claim index `claim` names: a row of [`ROUTES`], or past them one of the

#[must_use]
pub fn route_of_claim(claim: u32, agent_claims: impl FnOnce() -> usize) -> Option<&'static Route> {
    let i = usize::try_from(claim).ok()?;
    ROUTES
        .get(i)
        .or_else(|| (i < ROUTES.len().saturating_add(agent_claims())).then_some(&AGENT_ENDPOINT))
}

/// How many trailing-separator claims ([`agent_slash_claims`]) the agents named `agents` state.
#[must_use]
pub fn agent_claim_count<'a>(agents: impl IntoIterator<Item = &'a str>) -> usize {
    agents.into_iter().filter(|a| plain_segment(a)).count()
}

/// A route as the snapshot's claim ([`ServedRoute::claim_spec`]: an open route takes no inbound

fn dialect_claim(r: &Route) -> ClaimSpec {
    let mut spec = r.claim_spec();
    spec.refusal_dialect =
        u16::try_from(line_of(r).dialect().unwrap_or(DIALECT_DOCUMENT)).unwrap_or_default();
    spec
}

/// The audit row every admitted unit of this plane leaves, written as a `RECORD_AUDIT` record

pub const AUDIT_ACTION: &str = "agent.call";

/// The resource an agent's row names (the kernel's `agent_key`: `agent:<id>`).
#[must_use]
pub fn agent_resource(agent: &str) -> String {
    format!("agent:{agent}")
}

/// The resource busbar's extended card's row names: the plane pool (the `agents` section).
pub const PLANE_POOL_RESOURCE: &str = crate::CONFIG_SECTION;

/// The audit record write for `resource`, `applied` or rejected, its words in `arena`.
#[must_use]
pub fn audit_write(
    arena: &mut busbar_contract::abi::sdk::HostBuf<'_, u8>,
    resource: &str,
    applied: bool,
) -> busbar_contract::abi::plane::RecordWrite {
    use busbar_contract::abi::plane::{AUDIT_APPLIED, AUDIT_REJECTED, RECORD_AUDIT};
    busbar_contract::abi::plane::RecordWrite {
        kind: if applied {
            AUDIT_APPLIED
        } else {
            AUDIT_REJECTED
        },
        op: RECORD_AUDIT,
        key: arena.span(AUDIT_ACTION.as_bytes()),
        value: arena.span(resource.as_bytes()),
    }
}

#[cfg(test)]
#[path = "tests/statement.rs"]
mod tests;
