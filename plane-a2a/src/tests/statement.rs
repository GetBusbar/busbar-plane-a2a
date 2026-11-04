// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The door's declarations pass the dispatcher's own validators, and `read_agents_section` judges a
//! section with the grammar's words.

use super::*;
use busbar_contract::abi::plane::check::{
    check_admin_routes, check_record_chains, check_tail, check_trust_keys,
};
use busbar_contract::abi::plane::{CLAIM_EXACT, CLAIM_OPEN, CLAIM_PATTERN};

/// A fixture endpoint: the secure scheme and a reserved example host, spelled once for every test.
fn endpoint(host: &str, rest: &str) -> String {
    format!("https://{host}.example{rest}")
}

/// A one-entry `agents:` section named `name` whose endpoint is `url`.
fn one_agent(name: &str, url: &str) -> Vec<u8> {
    format!(r#"{{"{name}": {{"url": "{url}", "pin": {{"mechanism": "unpinned"}}}}}}"#).into_bytes()
}

/// The tail declares exactly the task kind as TerminalOnly: every other kind is purged by age.
#[test]
fn the_tail_declares_the_task_kind_as_terminal_only() {
    let retentions: Vec<(&str, u32)> = RECORD_RETENTIONS
        .iter()
        .map(|r| (s(RECORD_KINDS[r.kind as usize]), r.rule))
        .collect();
    assert_eq!(
        retentions,
        [(crate::records::KIND_TASK, Retention::TerminalOnly.code())]
    );
    assert_eq!(TAIL.record_retentions, RECORD_RETENTIONS.as_ptr());
    assert_eq!(TAIL.record_retentions_len, RECORD_RETENTIONS.len());
}

fn s(a: AbiStr) -> &'static str {
    if a.is_absent() {
        return "";
    }

    std::str::from_utf8(known_bytes(a)).expect("utf-8")
}

/// The tail's own strings, read back through the `&'static str` each was built from.
fn known_bytes(a: AbiStr) -> &'static [u8] {
    [
        SCOPE,
        LABEL,
        SUBJECT_NOUN,
        ADMIN_NOUN,
        AUDIT_KIND,
        CARD_SIGNING_DOMAIN,
        CARD_KID_PREFIX,
        "pin",
        "reverify_ttl",
        "recovery_backoff",
        PRIVATE_REACH_KEY,
        DEFAULT_REVERIFY_TTL,
        DEFAULT_RECOVERY_BACKOFF,
        "jws_issuer_key",
        "cert_spki",
        "mtls",
        "unpinned",
        crate::a2a::config::REFUSE_PASSTHROUGH_SECTION,
        crate::records::KIND_TASK,
        crate::records::KIND_TASK_EVENT,
        crate::records::KIND_PUSH_CONFIG,
        crate::records::KIND_CARD,
        crate::records::KIND_CARD_APPROVAL,
    ]
    .into_iter()
    .find(|c| c.as_ptr() == a.ptr() && c.len() == a.len())
    .expect("a tail string this test knows")
    .as_bytes()
}

#[test]
fn the_tail_passes_the_dispatchers_check() {
    assert_eq!(check_tail(TAIL), Ok(()));
    assert_eq!(check_trust_keys(TRUST_KEYS), Ok(()));
}

/// RED before ruling B1: the door declared no chain, so the host framed none. The task-event kind
/// is declared chained, length-prefixed with its scope digested (B1 ruling 1, coordinator
/// 2026-10-07), and passes the loader's check.
#[test]
fn the_tail_declares_the_task_chain() {
    assert_eq!(TAIL.record_chains_len(), 1);
    assert_eq!(TAIL.record_chains_ptr(), RECORD_CHAINS.as_ptr());
    let chains = RECORD_CHAINS;
    assert_eq!(
        check_record_chains(chains, TAIL.record_kinds_len() as u64),
        Ok(())
    );
    let chain = chains[0];
    assert_eq!(
        crate::records::HELD_KINDS[chain.kind as usize],
        crate::records::KIND_TASK_EVENT
    );
    assert_eq!(
        (chain.framing, chain.flags),
        (
            busbar_contract::abi::plane::CHAIN_LENGTH_PREFIXED,
            busbar_contract::abi::plane::CHAIN_DIGESTS_SCOPE
        )
    );
}

#[test]
fn the_tail_states_the_planes_nouns() {
    assert_eq!(s(TAIL.scope), SCOPE);
    assert_eq!(s(TAIL.subject_noun), SUBJECT_NOUN);
    assert_eq!(s(TAIL.admin_noun), ADMIN_NOUN);
    assert_eq!(s(TAIL.audit_kind), AUDIT_KIND);
    assert_eq!(s(TAIL.signing_domain), CARD_SIGNING_DOMAIN);
    assert_eq!(s(TAIL.signing_kid_prefix), CARD_KID_PREFIX);
    assert_eq!(TAIL.dialects_len(), 3);
    assert_eq!(TAIL.record_kinds_len(), crate::records::HELD_KINDS.len());
    for (abi, kind) in RECORD_KINDS.iter().zip(crate::records::HELD_KINDS) {
        assert_eq!(s(*abi), *kind);
    }
}

#[test]
fn the_tail_states_the_sentence_that_refuses_a_forwarded_caller_credential() {
    assert_eq!(
        s(TAIL.caller_credential_refusal),
        crate::a2a::config::REFUSE_PASSTHROUGH_SECTION
    );
}

#[test]
fn an_admitted_generation_claims_every_route_and_states_its_audience() {
    let spec = agents_snapshot_spec(Some(&endpoint("gw", "/base?x=1")), &["vendor", "other"]);
    assert_eq!(
        spec.claims.len(),
        ROUTES.len() + 2,
        "every route, then each agent's slash"
    );
    assert_eq!(spec.audience, Some(endpoint("gw", "/a2a")));
    assert_eq!(
        spec.resource_metadata,
        Some(endpoint("gw", "/.well-known/oauth-protected-resource/a2a"))
    );
    assert_eq!(spec.admin_routes.len(), ADMIN_ROUTES.len());
    assert_eq!(
        spec.openapi,
        Some(openapi_fragment("").to_string().into_bytes())
    );
}

#[test]
fn a_generation_with_no_readable_public_base_claims_nothing() {
    for public in [None, Some("not a url")] {
        let spec = agents_snapshot_spec(public, &["vendor"]);
        assert!(spec.claims.is_empty());
        assert_eq!((spec.audience, spec.resource_metadata), (None, None));
        assert_eq!(spec.admin_routes.len(), ADMIN_ROUTES.len());
    }
}

/// Ported from busbar-a2a plane_tests.rs::a_section_carrying_only_the_reserved_keys_is_still_no_plane
/// (its plane half; the mounted surface is the root's `agent_door` cell of the same name).
#[test]
fn a_section_carrying_only_the_reserved_keys_states_no_route_and_no_card() {
    use busbar_contract::abi::plane::ROUTE_PUBLIC;
    let cfg = read_agents_section(br#"{"hooks": ["audit"], "upstream_credentials": "own"}"#)
        .expect("the reserved keys alone are a section");
    assert!(cfg.agents.is_empty(), "it registers no agent");
    let names: Vec<&str> = cfg.agents.keys().map(String::as_str).collect();
    let spec = agents_snapshot_spec(Some(&endpoint("gw", "")), &names);
    assert!(
        spec.claims.is_empty(),
        "it claims no route: {:?}",
        spec.claims
    );
    assert_eq!((spec.audience, spec.resource_metadata), (None, None));
    assert!(
        spec.admin_routes
            .iter()
            .all(|r| r.flags & ROUTE_PUBLIC == 0),
        "no public route: {:?}",
        spec.admin_routes
    );
    let verbs: Vec<(&str, &str)> = spec
        .admin_routes
        .iter()
        .map(|r| (r.verb.as_str(), r.target.as_str()))
        .collect();
    assert_eq!(
        verbs,
        ADMIN_VERBS[..PUSH_ROUTE].to_vec(),
        "the trust verbs keep their indices"
    );
}

#[test]
fn the_admin_routes_pass_the_dispatchers_check() {
    assert_eq!(check_admin_routes(ADMIN_ROUTES), Ok(()));
}

#[test]
fn the_abi_admin_routes_are_the_admin_verbs() {
    assert_eq!(ADMIN_ROUTES.len(), ADMIN_VERBS.len());
    for (abi, (verb, target)) in ADMIN_ROUTES.iter().zip(ADMIN_VERBS) {
        assert_eq!(
            (abi.verb.ptr(), abi.verb.len()),
            (verb.as_ptr(), verb.len())
        );
        assert_eq!(
            (abi.target.ptr(), abi.target.len()),
            (target.as_ptr(), target.len())
        );
    }
}

#[test]
fn exactly_the_discovery_documents_are_open_claims() {
    let open: Vec<&str> = ROUTES.iter().filter(|r| r.open).map(|r| r.target).collect();
    assert_eq!(open, [crate::METADATA_PATH, crate::WELL_KNOWN_CARD_PATH]);
}

/// The push callback is the plane's only public route, served through `serve`.
#[test]
fn the_push_callback_is_a_public_route_and_no_claim() {
    use busbar_contract::abi::plane::{ROUTE_CARRIES_OWN_TOKEN, ROUTE_PUBLIC};
    assert_eq!(ADMIN_VERBS[PUSH_ROUTE], ("POST", "/a2a/push"));
    assert_eq!(
        ADMIN_ROUTES[PUSH_ROUTE].flags,
        ROUTE_PUBLIC | ROUTE_CARRIES_OWN_TOKEN
    );
    assert_eq!(
        ADMIN_AUDIT_VERBS[PUSH_ROUTE], "",
        "the callback is never audited"
    );
    for (i, r) in ADMIN_ROUTES.iter().enumerate() {
        assert_eq!(r.flags & ROUTE_PUBLIC != 0, i == PUSH_ROUTE);
        assert_eq!(r.flags & ROUTE_CARRIES_OWN_TOKEN != 0, i == PUSH_ROUTE);
    }
    assert!(ROUTES.iter().all(|r| r.target != "/a2a/push"));
}

#[test]
fn the_openapi_fragment_keys_its_paths_under_the_prefix_given() {
    let doc = openapi_fragment("/api/v1/admin");
    let mut keys: Vec<&String> = doc.as_object().expect("an object").keys().collect();
    keys.sort();
    assert_eq!(
        keys,
        [
            "/api/v1/admin/agents/{name}/approve",
            "/api/v1/admin/agents/{name}/connect",
            "components"
        ]
    );
}

/// Each trust verb's OpenAPI `200` response names its own body schema.
#[test]
fn the_admin_openapi_blob_states_every_body_its_verbs_name() {
    fn refs(v: &serde_json::Value, out: &mut Vec<String>) {
        match v {
            serde_json::Value::Object(m) => {
                if let Some(r) = m.get("$ref").and_then(|r| r.as_str()) {
                    out.push(r.to_string());
                }
                m.values().for_each(|v| refs(v, out));
            }
            serde_json::Value::Array(a) => a.iter().for_each(|v| refs(v, out)),
            _ => {}
        }
    }
    let blob: serde_json::Value = serde_json::from_str(ADMIN_OPENAPI).expect("a JSON object");
    let schemas = blob["components"]["schemas"]
        .as_object()
        .expect("the blob states its schemas");
    for (i, (verb, target)) in ADMIN_VERBS.iter().enumerate() {
        if i == PUSH_ROUTE {
            continue;
        }
        let op = &blob[*target][verb.to_ascii_lowercase()];
        let body = &op["responses"]["200"]["content"]["application/json"]["schema"]["$ref"];
        assert!(body.is_string(), "{verb} {target} names no typed body");
    }
    let mut named = Vec::new();
    refs(&blob, &mut named);
    for r in &named {
        let name = r
            .strip_prefix("#/components/schemas/")
            .unwrap_or_else(|| panic!("`{r}` is no component reference"));
        assert!(schemas.contains_key(name), "`{r}` names no stated schema");
    }
    for name in schemas.keys() {
        assert!(
            named.iter().any(|r| r.ends_with(&format!("/{name}"))),
            "the blob states `{name}` and nothing names it"
        );
    }
}

#[test]
fn an_empty_blob_is_the_empty_section() {
    assert_eq!(
        read_agents_section(b"").expect("empty"),
        AgentsCfg::default()
    );
}

#[test]
fn a_valid_section_reads_and_a_bad_entry_is_refused_in_the_grammars_words() {
    let ok = one_agent("vendor", &endpoint("vendor", "/a2a"));
    assert_eq!(read_agents_section(&ok).expect("valid").agents.len(), 1);
    let bad = one_agent("vendor", "ftp://vendor.example");
    let err = read_agents_section(&bad).expect_err("refused");
    assert!(err.contains("`agents.vendor`: `url:` must be an"), "{err}");
}

/// THE HOST'S FAILOVER POOLS at the section's reserved `pools` key (the neutral top-level `pools:`
#[test]
fn the_hosts_failover_pools_are_lifted_off_the_section_in_declared_order() {
    let (b, a) = (
        endpoint("vendor", "/planner-b"),
        endpoint("vendor", "/planner-a"),
    );
    let section = format!(
        r#"{{"planner-b": {{"url": "{b}", "pin": {{"mechanism": "unpinned"}}}},
            "pools": {{"planner": {{"members": ["planner-b", {{"name": "planner-a"}}],
                                    "repeatable": [], "member_granted": true}}}},
            "planner-a": {{"url": "{a}", "pin": {{"mechanism": "unpinned"}}}}}}"#
    );
    let cfg = read_agents_section(section.as_bytes()).expect("the section reads");
    assert_eq!(
        cfg.agents.keys().collect::<Vec<_>>(),
        ["planner-b", "planner-a"],
        "the registrations, as written; `pools` is none of them"
    );
    assert_eq!(cfg.pools["planner"], ["planner-b", "planner-a"]);
    assert_eq!(
        cfg.pool_of("planner-a"),
        Some((
            "planner",
            ["planner-b".to_string(), "planner-a".to_string()].as_slice()
        ))
    );
    assert_eq!(cfg.pool_of("vendor"), None);

    let plain = one_agent("vendor", &endpoint("vendor", "/a2a"));
    assert!(read_agents_section(&plain).expect("valid").pools.is_empty());
}

#[test]
fn every_route_is_one_line_of_the_dialect_in_mount_order() {
    use Line::{Document, Framed, Open, Target};
    let lines: Vec<Line> = ROUTES.iter().map(line_of).collect();
    assert_eq!(
        lines,
        [
            Target, Target, Target, Target, Target, Target, Target, Target, Target, Target, Open,
            Open, Open, Open, Document, Document, Document, Framed,
        ]
    );

    let lens: Vec<usize> = [Document, Target, Framed]
        .iter()
        .map(|l| DIALECTS[l.dialect().expect("a line") as usize].len())
        .collect();
    assert_eq!(
        lens,
        [
            BINDING_DOCUMENT.len(),
            BINDING_TARGET.len(),
            BINDING_FRAMED.len()
        ]
    );
    assert_eq!(Open.dialect(), None);
}

/// THE DEALT VALIDATE BLOB: the boot's deal hands `{agents: <section>}`, which is unwrapped to the
/// section; a bare section passes through as it is.
#[test]
fn a_dealt_validate_blob_is_unwrapped_to_its_section() {
    let dealt =
        br#"{"agents":{"probe":{"url":"https://a.example/","pin":{"mechanism":"unpinned"}}}}"#;
    let section: serde_json::Value =
        serde_json::from_slice(&crate::statement::dealt_section(dealt)).expect("JSON");
    assert_eq!(
        section,
        serde_json::json!({"probe": {"url": "https://a.example/", "pin": {"mechanism": "unpinned"}}})
    );
    let bare = br#"{"probe":{"url":"https://a.example/"},"hooks":[]}"#;
    assert_eq!(&*crate::statement::dealt_section(bare), &bare[..]);
    assert!(crate::statement::read_agents_section(&crate::statement::dealt_section(dealt)).is_ok());
}

/// Two constants, and both are wire-visible: the credential kind appears on a stored credential row
/// and the scope kind on every scope reference an operator writes.
#[test]
fn the_credential_kind_and_the_scope_kind_are_the_spellings_the_rest_of_the_tree_uses() {
    assert_eq!(
        crate::served_card::CREDENTIAL_KIND_A2A_INBOUND,
        "a2a_inbound"
    );
    assert_eq!(SCOPE, "agent");
    assert_eq!(s(TAIL.scope), "agent");
}
/// THE AGENT FEE (the engine's `agents.fees`): the door counts `per_request` and only it, so the
/// kernel's one rule over declared fee units validates `agents.fees.per_request` and refuses
/// `agents.fees.per_session` naming `per_request` as the counted list; the fee unit is a billable
/// class at the index the door reports it under, once per served unit.
#[test]
fn the_door_counts_the_per_request_fee_and_never_a_per_session_one() {
    let same = |a: AbiStr, b: &str| a.ptr() == b.as_ptr() && a.len() == b.len();
    assert_eq!(FEE_PER_REQUEST, busbar_contract::plane::PER_REQUEST);
    assert_ne!(FEE_PER_REQUEST, busbar_contract::plane::PER_SESSION);
    assert_eq!(FEE_UNITS.len(), 1, "one fee unit");
    assert!(same(FEE_UNITS[0], FEE_PER_REQUEST));
    assert!(same(
        BILLABLE_CLASSES[CLASS_FEE_INDEX as usize].class,
        FEE_PER_REQUEST
    ));
}
/// Ported from `busbar-a2a` `creds_tests::the_callers_credential_has_no_path_to_a_delegate`, its
/// config half: the per-entry value that would mean "forward the caller's credential"
/// (`upstream_credentials: passthrough`) is refused at validation in the plane's own sentence, and
/// `own` is accepted, so the refusal is about the value and not the key.
#[test]
fn the_callers_credential_has_no_path_to_a_delegate() {
    let def = |extra: serde_json::Value| -> crate::a2a::config::AgentDefCfg {
        let mut entry = serde_json::json!({
            "url": "https://a2a.vendor/planner",
            "pin": { "mechanism": "unpinned" },
        });
        if let (Some(entry), Some(extra)) = (entry.as_object_mut(), extra.as_object()) {
            entry.extend(extra.clone());
        }
        serde_json::from_value(entry).expect("the shape is legal; the VALUE is what is judged")
    };
    let validate = |extra| crate::a2a::config::validate_agent("planner", &def(extra));
    let err = validate(serde_json::json!({ "upstream_credentials": "passthrough" }))
        .expect_err("passthrough is refused on the agents: plane");
    assert!(
        err.contains(crate::a2a::config::REFUSE_PASSTHROUGH_SECTION),
        "the refusal explains itself: {err}"
    );
    validate(serde_json::json!({ "upstream_credentials": "own" }))
        .expect("`own` is the supported mode");

    let secret = serde_json::json!({ "env": "PLANNER_KEY" });
    validate(serde_json::json!({
        "upstream_credential": { "secret": secret, "lease_ttl_ms": 30000 }
    }))
    .expect("a lease over zero");
    let err = validate(serde_json::json!({
        "upstream_credential": { "secret": secret, "lease_ttl_ms": 0 }
    }))
    .expect_err("zero");
    assert!(err.contains("lease_ttl_ms"), "{err}");
    let err = validate(serde_json::json!({
        "upstream_credential": {
            "secret": secret, "placement": { "header": " " }, "lease_ttl_ms": 1
        }
    }))
    .expect_err("blank");
    assert!(err.contains("placement.header"), "{err}");
}
/// RED: the grammar's object spelling of a named-header placement, `placement: {header: <name>}`
#[test]
fn a_named_header_placement_reads_through_the_section() {
    use crate::a2a::creds::CredentialPlacement;
    let placed = |placement: serde_json::Value| {
        let section = serde_json::json!({ "planner": {
            "url": "https://a2a.vendor/planner",
            "pin": { "mechanism": "unpinned" },
            "upstream_credential": {
                "secret": { "env": "PLANNER_KEY" }, "placement": placement, "lease_ttl_ms": 1000
            },
        } });
        crate::statement::read_agents_section(&serde_json::to_vec(&section).unwrap()).map(|cfg| {
            cfg.agents["planner"]
                .upstream_credential
                .clone()
                .unwrap()
                .placement
        })
    };
    assert_eq!(
        placed(serde_json::json!({ "header": "X-API-Key" })),
        Ok(CredentialPlacement::Header("X-API-Key".to_string()))
    );
    assert_eq!(
        placed(serde_json::json!("bearer")),
        Ok(CredentialPlacement::AuthorizationHeader)
    );
    assert!(placed(serde_json::json!("cookie")).is_err());
    assert!(placed(serde_json::json!({ "header": "a", "bearer": null })).is_err());
}

/// Ported from busbar-a2a a2a/tests/plane_tests.rs::the_registry_follows_config_order_rather_than_hash_order.
#[test]
fn the_registry_follows_config_order_rather_than_hash_order() {
    let blob = format!(
        "{{{}}}",
        ["zeta", "alpha", "mid"]
            .iter()
            .map(|n| format!(
                r#""{n}": {{"url": "{}", "pin": {{"mechanism": "unpinned"}}}}"#,
                endpoint(n, "/a2a")
            ))
            .collect::<Vec<_>>()
            .join(",")
    );
    let cfg = read_agents_section(blob.as_bytes()).expect("a valid section");
    let ids: Vec<&str> = cfg.agents.keys().map(String::as_str).collect();
    assert_eq!(
        ids,
        ["zeta", "alpha", "mid"],
        "the section keeps the order an operator wrote, not hash or sorted order"
    );
}

/// Ported from busbar-a2a a2a/tests/serve_tests.rs::every_published_binding_is_one_the_a2a_plane_declares_a_wire_format_for.
#[test]
fn every_published_binding_is_one_the_a2a_plane_declares_a_wire_format_for() {
    use crate::binding::{BINDING_DOCUMENT, BINDING_FRAMED, BINDING_TARGET};
    let declared: Vec<&str> = [BINDING_DOCUMENT, BINDING_TARGET, BINDING_FRAMED].to_vec();

    assert_eq!(DIALECTS.len(), declared.len());
    for (abi, name) in DIALECTS.iter().zip(&declared) {
        assert_eq!((abi.ptr(), abi.len()), (name.as_ptr(), name.len()));
    }

    let upper: Vec<String> = declared.iter().map(|d| d.to_uppercase()).collect();
    assert_eq!(
        crate::served_card::SERVABLE_BINDINGS,
        upper.iter().map(String::as_str).collect::<Vec<_>>()
    );
    let own = crate::served_card::self_card_document("https://gw.example", Vec::new())
        .expect("busbar's own card");
    for iface in own["supportedInterfaces"].as_array().expect("interfaces") {
        let binding = iface["protocolBinding"].as_str().expect("binding");
        assert!(
            upper.iter().any(|d| d.eq_ignore_ascii_case(binding)),
            "busbar's own card publishes `{binding}`, which the plane does not declare"
        );
    }

    for b in crate::served_card::AGENT_ADDRESS_BINDINGS {
        assert!(upper.iter().any(|d| d == b), "{b}");
    }
}

/// Ported from busbar-a2a a2a/tests/serve_tests.rs::the_plane_declares_its_published_identity_and_its_claims_speak_its_wire_formats.
#[test]
fn the_plane_declares_its_published_identity_and_its_claims_speak_its_wire_formats() {
    assert_eq!(crate::PLANE_KEY, "a2a");
    assert_eq!(crate::CONFIG_SECTION, "agents");
    assert_eq!(AUDIT_KIND, "a2a_agent");
    assert_eq!(format!("{AUDIT_KIND}.connect"), "a2a_agent.connect");
    assert_eq!(format!("{AUDIT_KIND}.approve"), "a2a_agent.approve");
    assert_eq!(SUBJECT_NOUN, "fronted agent");
    assert_eq!(SCOPE, "agent");
    assert_eq!(s(TAIL.audit_kind), "a2a_agent");
    assert_eq!(s(TAIL.subject_noun), "fronted agent");
    assert_eq!(TAIL.scope_kinds_len(), 1);
    assert_eq!(s(TAIL.scope), "agent");
    assert_eq!(crate::binding::BINDING_DOCUMENT, "jsonrpc");
    assert_eq!(crate::binding::BINDING_TARGET, "http+json");
    assert_eq!(crate::binding::BINDING_FRAMED, "grpc");
    assert_eq!(TAIL.dialects_len(), 3);

    let spec = agents_snapshot_spec(Some(&endpoint("gw", "")), &["vendor"]);
    assert!(!spec.claims.is_empty());
    for c in &spec.claims {
        assert!(
            c.carrier == crate::claims::DOCUMENT_TRANSPORT
                || c.carrier == crate::claims::FRAMED_TRANSPORT,
            "a claim over an undeclared carrier: {}",
            c.carrier
        );
        assert!(
            c.target.starts_with(crate::MOUNT_PATH)
                || c.target.starts_with(crate::framed::SERVICE_PATH)
                || c.target.starts_with("/.well-known/"),
            "a claim outside the plane's mounts: {}",
            c.target
        );
    }

    assert!(agents_snapshot_spec(None, &["vendor"]).claims.is_empty());
}

/// The Statement declares counters for the drop-oldest push queue.
#[test]
fn the_statement_declares_the_push_queue_counters() {
    let st = crate::plane_door::STATEMENT;
    assert_eq!(st.families_len, FAMILIES.len());
    assert_eq!(FAMILIES.len(), 2);
    for (index, name) in [
        (FAMILY_PUSH_DROPPED, METRIC_PUSH_DROPPED),
        (FAMILY_PUSH_UNFILED, METRIC_PUSH_UNFILED),
    ] {
        let family = &FAMILIES[index as usize];
        assert_eq!(s(family.name), name, "{name}");
        assert_eq!(
            family.kind,
            busbar_contract::abi::mechanism::door::FAMILY_COUNTER
        );
        assert_eq!(family.label_keys_len, 0);
    }
}

/// Every configured agent claims its endpoint with a trailing separator.
#[test]
fn each_fronted_agent_claims_its_endpoint_with_a_trailing_separator() {
    let spec = agents_snapshot_spec(Some(&endpoint("gw", "")), &["vendor", "other"]);
    let slash: Vec<(&str, &str)> = spec.claims[ROUTES.len()..]
        .iter()
        .map(|c| (c.verb.as_str(), c.target.as_str()))
        .collect();
    assert_eq!(
        slash,
        [
            ("POST", "/a2a/agents/vendor/"),
            ("POST", "/a2a/agents/other/")
        ]
    );
    for c in &spec.claims[ROUTES.len()..] {
        assert_eq!(c.flags & CLAIM_EXACT, CLAIM_EXACT, "{}", c.target);
        assert_eq!(c.flags & (CLAIM_PATTERN | CLAIM_OPEN), 0, "{}", c.target);
        assert_eq!(
            busbar_contract::abi::plane::check::check_claim_target(&c.target, c.flags),
            Ok(()),
            "{}",
            c.target
        );
        assert_eq!(u32::from(c.refusal_dialect), DIALECT_DOCUMENT);
    }
    let n = u32::try_from(ROUTES.len()).expect("a small table");
    assert_eq!(route_of_claim(n, || 2), Some(&AGENT_ENDPOINT));
    assert_eq!(route_of_claim(n + 1, || 2), Some(&AGENT_ENDPOINT));
    assert_eq!(
        route_of_claim(n + 2, || 2),
        None,
        "past the generation's claims: unclaimed"
    );
    assert_eq!(
        route_of_claim(n, || 0),
        None,
        "a generation fronting no agent states none"
    );
    assert_eq!(
        line_of(route_of_claim(n, || 1).expect("a route")),
        Line::Document
    );
    assert_eq!(agent_claim_count(["vendor", "a/b", "other"]), 2);
    assert_eq!(agent_slash_target("a/b"), None);
    assert_eq!(agent_slash_target(".."), None);
    assert_eq!(agent_slash_target(""), None);
    assert!(agent_slash_claims(&["a b", "ok"]).len() == 1);
}

#[test]
fn malformed_credential_structs_do_not_echo_secret_scalars() {
    for field in ["upstream_credential", "client_identity"] {
        let value = serde_json::json!({"planner": {"url":"https://agent.example", "pin":{"mechanism":"unpinned"}, field: "secret-scalar-never-log"}});
        let error = read_section(&serde_json::to_vec(&value).unwrap()).unwrap_err();
        assert!(!error.contains("secret-scalar-never-log"));
    }
}
