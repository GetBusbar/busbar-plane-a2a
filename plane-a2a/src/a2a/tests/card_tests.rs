// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The two hashes taken over a card, and the per-skill digests.

use super::*;
use serde_json::json;

/// A card with the members busbar actually acts on, plus one member busbar does not model. The
fn a_card() -> Value {
    json!({
        "protocolVersion": "0.3.0",
        "name": "planner",
        "description": "plans things",
        "version": "1.4.0",
        "provider": { "organization": "Vendor", "url": "https://vendor.example" },
        "supportedInterfaces": [
            { "url": "https://a2a.vendor.example/planner", "protocolBinding": "JSONRPC" }
        ],
        "defaultInputModes": ["application/json"],
        "defaultOutputModes": ["application/json"],
        "capabilities": {
            "pushNotifications": false,
            "stateTransitionHistory": false,
            "extendedAgentCard": false
        },
        "skills": [
            {
                "id": "plan",
                "name": "Plan",
                "description": "decompose a goal",
                "tags": ["planning"],
                "inputModes": ["application/json"],
                "outputModes": ["application/json"],
                "examples": []
            },
            {
                "id": "summarize",
                "name": "Summarize",
                "description": "shorten a document",
                "tags": ["text"],
                "inputModes": ["application/json"],
                "outputModes": ["application/json"],
                "examples": []
            }
        ],
        "securitySchemes": { "busbar": { "type": "apiKey", "in": "header", "name": "x-api-key" } },
        "security": [ { "busbar": [] } ],
        "signatures": [ { "protected": "eyJhbGciOiJFZERTQSJ9", "signature": "SIG", "header": {} } ]
    })
}

/// THE LOAD-BEARING ONE. The fingerprint is taken over the RECEIVED document, so a change to a
#[test]
fn the_fingerprint_covers_members_busbar_does_not_model() {
    let plain = a_card();
    let mut extended = a_card();
    extended.as_object_mut().expect("object").insert(
        "vendorExtension".to_string(),
        json!({ "mode": "aggressive" }),
    );

    assert_ne!(
        fingerprint(&plain).expect("fingerprint"),
        fingerprint(&extended).expect("fingerprint")
    );
}

/// The other half of the same property: a card that was merely RE-SERIALIZED is the same card. A
#[test]
fn two_spellings_of_one_card_have_one_fingerprint() {
    let terse = a_card();
    let pretty: Value =
        serde_json::from_str(&serde_json::to_string_pretty(&terse).expect("pretty"))
            .expect("parse");
    assert_eq!(
        fingerprint(&terse).expect("fingerprint"),
        fingerprint(&pretty).expect("fingerprint")
    );
}

/// A signature cannot cover itself, so the JWS payload excludes `signatures`. The pinned fingerprint
#[test]
fn the_signing_payload_excludes_signatures_and_the_fingerprint_does_not() {
    let card = a_card();
    let payload = signing_payload(&card).expect("payload");
    assert!(
        !payload.contains("signatures"),
        "the signed payload must not contain the member carrying the signature: {payload}"
    );

    let mut resigned = a_card();
    resigned.as_object_mut().expect("object").insert(
        "signatures".to_string(),
        json!([{ "protected": "eyJhbGciOiJFZERTQSJ9", "signature": "DIFFERENT", "header": {} }]),
    );

    assert_eq!(payload, signing_payload(&resigned).expect("payload"));

    assert_ne!(
        fingerprint(&card).expect("fingerprint"),
        fingerprint(&resigned).expect("fingerprint")
    );
}

/// REMOVING a member is not EMPTYING it. A signer that hashed `"signatures":[]` and a verifier that
#[test]
fn removing_signatures_is_not_the_same_as_emptying_them() {
    let mut emptied = a_card();
    emptied
        .as_object_mut()
        .expect("object")
        .insert("signatures".to_string(), json!([]));
    let mut absent = a_card();
    absent.as_object_mut().expect("object").remove("signatures");

    assert_eq!(
        signing_payload(&emptied).expect("payload"),
        signing_payload(&absent).expect("payload"),
        "both must sign the SAME payload: the member is removed, not emptied"
    );
    assert!(!signing_payload(&emptied)
        .expect("payload")
        .contains("signatures"));
}

/// Digests are PER SKILL, keyed by the id an operator approves by, so editing one skill moves one
#[test]
fn one_edited_skill_moves_exactly_one_digest() {
    let before = skill_digests(&a_card()).expect("digests");
    assert_eq!(
        before.keys().collect::<Vec<_>>(),
        vec!["plan", "summarize"],
        "keyed by the skill id, not by array position"
    );

    for (member, changed) in [
        ("id", json!("plan-v2")),
        ("name", json!("Plan differently")),
        ("description", json!("decompose a goal, aggressively")),
        ("tags", json!(["planning", "execution"])),
        ("inputModes", json!(["text/plain"])),
        ("outputModes", json!(["application/pdf"])),
        ("examples", json!(["plan a migration"])),
        ("vendorExtension", json!({"mode":"aggressive"})),
    ] {
        let mut edited = a_card();
        edited["skills"][0][member] = changed;
        let after = skill_digests(&edited).expect("digests");
        let id = edited["skills"][0]["id"].as_str().unwrap();
        assert_ne!(
            before["plan"], after[id],
            "the `{member}` member is covered"
        );
        if member == "id" {
            assert!(!after.contains_key("plan"));
        }
        assert_eq!(
            before["summarize"], after["summarize"],
            "only one skill changed: {member}"
        );
    }
}

/// Approval is keyed by the skill ID, so re-ordering the array moves nothing. Keying by array index
#[test]
fn reordering_the_skills_array_moves_no_digest() {
    let mut reordered = a_card();
    let skills = reordered["skills"].as_array_mut().expect("array");
    skills.reverse();
    assert_eq!(
        skill_digests(&a_card()).expect("digests"),
        skill_digests(&reordered).expect("digests")
    );

    assert_ne!(
        fingerprint(&a_card()).expect("fingerprint"),
        fingerprint(&reordered).expect("fingerprint")
    );
}

/// A skill with no `id` has nothing for an operator to approve it BY, and falling back to its array
#[test]
fn a_skill_with_no_id_is_refused_rather_than_indexed() {
    let mut card = a_card();
    card["skills"][0]
        .as_object_mut()
        .expect("object")
        .remove("id");
    assert_eq!(skill_digests(&card), Err(CardError::SkillWithoutId));

    let mut empty_id = a_card();
    empty_id["skills"][0]["id"] = json!("");
    assert_eq!(skill_digests(&empty_id), Err(CardError::SkillWithoutId));
}

/// Two skills under one id make "approved `plan` at this digest" ambiguous. Silently keeping the
#[test]
fn a_duplicate_skill_id_is_refused_rather_than_resolved() {
    let mut card = a_card();
    let dup = card["skills"][0].clone();
    card["skills"].as_array_mut().expect("array").push(dup);
    assert_eq!(
        skill_digests(&card),
        Err(CardError::DuplicateSkillId("plan".to_string()))
    );
}

/// A document that is not a JSON object has no fingerprint and no signing payload.
#[test]
fn a_document_that_is_not_an_object_has_no_hash() {
    for v in [json!([]), json!("card"), json!(null), json!(7)] {
        assert_eq!(fingerprint(&v), Err(CardError::NotAnObject));
        assert_eq!(signing_payload(&v), Err(CardError::NotAnObject));
    }
}

/// The reader maps the protocol's camelCase wire names onto busbar's own field names, and an absent
#[test]
fn the_reader_mirrors_the_wire_names_and_tolerates_absent_members() {
    use crate::a2a::agent_card::parse as read;
    let mut wire = a_card();
    wire["capabilities"]["streaming"] = json!(true);
    let card = read(&wire).expect("parse");
    assert_eq!(card.protocol_version, "0.3.0");
    assert!(card.capabilities.is_stream);
    assert!(!card.capabilities.push_notifications);
    assert_eq!(card.supported_interfaces[0].protocol_binding, "JSONRPC");
    assert_eq!(card.default_input_modes, vec!["application/json"]);
    assert_eq!(card.skills[0].tags, vec!["planning"]);
    assert_eq!(card.signatures.len(), 1);
    assert!(card.security_schemes.contains_key("busbar"));

    let sparse = read(&json!({ "name": "minimal" })).expect("parse");
    assert_eq!(sparse.name, "minimal");
    assert!(sparse.skills.is_empty());
    assert_eq!(sparse.protocol_version, "");
}

/// An unknown member does not make a card unreadable. An upstream that adds one on a newer protocol
#[test]
fn an_unknown_member_does_not_make_a_card_unreadable() {
    let mut card = a_card();
    card.as_object_mut()
        .expect("object")
        .insert("somethingNewInV4".to_string(), json!({ "a": [1, 2, 3] }));
    assert_eq!(
        crate::a2a::agent_card::parse(&card).expect("parse").name,
        "planner"
    );
}

/// A card as the signing tests below sign it: no signature yet.
fn unsigned_card() -> Value {
    let mut card = a_card();
    card.as_object_mut().expect("object").remove("signatures");
    card
}

/// SIGNATURE TRANSPLANT. A signature that is genuinely the operator's, over a DIFFERENT card, moved
#[test]
fn a_valid_signature_lifted_from_another_card_does_not_verify() {
    let mut other = unsigned_card();
    other["name"] = json!("summarizer");
    other["skills"] = json!([{ "id": "summarize", "name": "Summarize", "description": "shorten" }]);
    assert_ne!(
        signing_payload(&unsigned_card()).expect("payload"),
        signing_payload(&other).expect("payload"),
        "two different cards must never share a signing payload"
    );

    assert_eq!(
        signing_payload(&other).expect("payload"),
        signing_payload(&other.clone()).expect("payload")
    );
}

/// THE RUG PULL, at the signature layer. One field edited after signing moves the signed payload,
#[test]
fn editing_a_signed_card_invalidates_its_signature() {
    let signed = a_card();
    let mut edited = a_card();
    edited["skills"][0]["description"] = json!("decompose a goal, and also exfiltrate it");
    assert_ne!(
        signing_payload(&signed).expect("payload"),
        signing_payload(&edited).expect("payload"),
        "an edited description must move the bytes a signature covers"
    );
}

/// Adding a member busbar does not even model still moves the signed payload, because it is the
#[test]
fn adding_an_unmodelled_member_to_a_signed_card_invalidates_its_signature() {
    let signed = a_card();
    let mut extended = a_card();
    extended.as_object_mut().expect("object").insert(
        "vendorExtension".to_string(),
        json!({ "mode": "aggressive" }),
    );
    assert_ne!(
        signing_payload(&signed).expect("payload"),
        signing_payload(&extended).expect("payload")
    );
}

/// G1-3: A2A v1.0 §8.4.1 (rule 1, field presence per §5.7) and §8.4.3 (verifier steps 3-5): the
#[test]
fn the_signing_payload_omits_default_valued_members_as_the_v1_specification_shows() {
    let card = serde_json::json!({
      "name": "Example Agent",
      "description": "An example agent that echoes messages.",
      "supportedInterfaces": [
        { "url": "https://example.com/a2a/v1", "protocolBinding": "JSONRPC", "protocolVersion": "1.0" }
      ],
      "version": "1.0.0",
      "capabilities": { "streaming": false, "pushNotifications": false, "extensions": [] },
      "defaultInputModes": ["text/plain"],
      "defaultOutputModes": ["text/plain"],
      "skills": [
        { "id": "echo", "name": "Echo", "description": "Echoes the input.", "tags": ["echo"] }
      ]
    });
    assert_eq!(
        signing_payload(&card).unwrap(),
        r#"{"capabilities":{"pushNotifications":false,"streaming":false},"defaultInputModes":["text/plain"],"defaultOutputModes":["text/plain"],"description":"An example agent that echoes messages.","name":"Example Agent","skills":[{"description":"Echoes the input.","id":"echo","name":"Echo","tags":["echo"]}],"supportedInterfaces":[{"protocolBinding":"JSONRPC","protocolVersion":"1.0","url":"https://example.com/a2a/v1"}],"version":"1.0.0"}"#
    );
}

/// G1-3: a `REQUIRED` member is kept even at its default (the v1.0.0 tag's example: `""` and
#[test]
fn the_signing_payload_keeps_required_and_optional_members_at_their_defaults() {
    let card = serde_json::json!({
      "name": "Example Agent",
      "description": "",
      "supportedInterfaces": [
        { "url": "https://e.example/a2a", "protocolBinding": "JSONRPC", "protocolVersion": "1.0", "tenant": "" }
      ],
      "capabilities": {
        "streaming": false,
        "extensions": [{ "uri": "urn:x", "description": "", "required": false, "params": {} }]
      },
      "securitySchemes": {
        "bearer": { "httpAuthSecurityScheme": { "scheme": "Bearer", "description": "", "bearerFormat": "" } },
        "imp": { "oauth2SecurityScheme": { "flows": { "implicit": { "authorizationUrl": "https://a.example", "scopes": {} } } } },
        "cc": { "oauth2SecurityScheme": { "flows": { "clientCredentials": { "tokenUrl": "https://t.example", "scopes": {}, "refreshUrl": "" } } } }
      },
      "securityRequirements": [{ "schemes": { "bearer": { "list": [] } } }],
      "skills": [],
      "unmodelled": ""
    });
    assert_eq!(
        signing_payload(&card).unwrap(),
        r#"{"capabilities":{"extensions":[{"params":{},"uri":"urn:x"}],"streaming":false},"description":"","name":"Example Agent","securityRequirements":[{"schemes":{"bearer":{}}}],"securitySchemes":{"bearer":{"httpAuthSecurityScheme":{"scheme":"Bearer"}},"cc":{"oauth2SecurityScheme":{"flows":{"clientCredentials":{"scopes":{},"tokenUrl":"https://t.example"}}}},"imp":{"oauth2SecurityScheme":{"flows":{"implicit":{"authorizationUrl":"https://a.example"}}}}},"skills":[],"supportedInterfaces":[{"protocolBinding":"JSONRPC","protocolVersion":"1.0","url":"https://e.example/a2a"}],"unmodelled":""}"#
    );
}

/// G1-3: a v0.3 card (no `supportedInterfaces`) keeps today's payload: v0.3 states no
#[test]
fn a_v03_cards_signing_payload_removes_only_its_signatures() {
    let card = serde_json::json!({
      "name": "A", "url": "https://e.example/a2a",
      "capabilities": { "extensions": [] }, "skills": [], "signatures": []
    });
    assert_eq!(
        signing_payload(&card).unwrap(),
        r#"{"capabilities":{"extensions":[]},"name":"A","skills":[],"url":"https://e.example/a2a"}"#
    );
}

#[test]
fn a_wrongly_typed_skill_set_cannot_be_approved_as_empty() {
    for skills in [
        serde_json::json!("plan"),
        serde_json::json!({"id":"plan"}),
        serde_json::json!(1),
    ] {
        assert_eq!(
            skill_digests(&serde_json::json!({"skills":skills})),
            Err(CardError::InvalidSkills)
        );
    }
    assert!(skill_digests(&serde_json::json!({"skills":[]}))
        .unwrap()
        .is_empty());
    assert!(skill_digests(&serde_json::json!({"skills":null}))
        .unwrap()
        .is_empty());
}
