// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE AGENT CARD, as the plane reads it: busbar's own structs, transcribed from the A2A specification.

use std::collections::BTreeMap;

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

/// The organization behind an agent. Operator-facing provenance, never an authenticity claim.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct AgentProvider {
    /// The organization's name.
    #[serde(deserialize_with = "nullable")]
    pub organization: String,
    /// The organization's URL.
    #[serde(deserialize_with = "nullable")]
    pub url: String,
}

/// One endpoint an agent can be reached on, and the wire format it speaks there.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct AgentInterface {
    /// The endpoint the card names (never dialled: the operator's `url:` says where).
    #[serde(deserialize_with = "nullable")]
    pub url: String,
    /// The binding's card word: `JSONRPC`, `HTTP+JSON` or `GRPC`.
    #[serde(deserialize_with = "nullable")]
    pub protocol_binding: String,
}

/// The optional protocol features an agent claims. Read by catalogue construction as STRUCTURAL
/// fitness (can this agent accept this shape of task at all), never as a quality signal.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct AgentCapabilities {
    /// The agent streams (`streaming`).
    #[serde(rename = "streaming")]
    #[serde(deserialize_with = "nullable")]
    pub is_stream: bool,
    /// The agent delivers push notifications.
    #[serde(deserialize_with = "nullable")]
    pub push_notifications: bool,
    /// The agent keeps its tasks' state history.
    #[serde(deserialize_with = "nullable")]
    pub state_transition_history: bool,
    /// The agent serves an authenticated extended card.
    #[serde(deserialize_with = "nullable")]
    pub extended_agent_card: bool,
}

/// One declared skill. THESE FIELDS ARE UPSTREAM-AUTHORED, and the trust model is built on knowing
/// that: an operator approving a card is vouching for what it claims, not verifying it. What the
/// digest of this structure buys is that the claim cannot CHANGE after the vouch without registering
/// as drift.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct AgentSkill {
    /// The skill's id: what an approval and a request name it by.
    #[serde(deserialize_with = "nullable")]
    pub id: String,
    /// Its name.
    #[serde(deserialize_with = "nullable")]
    pub name: String,
    /// Its description.
    #[serde(deserialize_with = "nullable")]
    pub description: String,
    /// Tags GROUP. They are never how one specific skill is named.
    #[serde(deserialize_with = "nullable")]
    pub tags: Vec<String>,
    /// The MIME modes it accepts; the card's defaults where empty.
    #[serde(deserialize_with = "nullable")]
    pub input_modes: Vec<String>,
    /// The MIME modes it produces; the card's defaults where empty.
    #[serde(deserialize_with = "nullable")]
    pub output_modes: Vec<String>,
    /// Example prompts.
    #[serde(deserialize_with = "nullable")]
    pub examples: Vec<String>,
}

/// A JWS signature over the card. Retained so an operator view can show WHICH key signed, and so a
/// card carrying several signatures is not silently reduced to its first.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct AgentCardSignature {
    /// The JWS protected header.
    #[serde(deserialize_with = "nullable")]
    pub protected: String,
    /// The JWS signature.
    #[serde(deserialize_with = "nullable")]
    pub signature: String,
    /// The JWS unprotected header.
    #[serde(deserialize_with = "nullable")]
    pub header: BTreeMap<String, Value>,
}

/// The Agent Card as busbar reads it.
///
/// `security_schemes` is carried as an open map rather than a mirrored union, and that is stated
/// rather than hidden: the schemes are an open, growing set, and half-mirroring a union produces a
/// struct that silently drops the arm it did not know about. busbar reads the scheme NAMES a caller
/// must satisfy; the scheme bodies travel verbatim and are hashed with the rest of the card.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct AgentCard {
    /// The A2A protocol version the card is written in.
    #[serde(deserialize_with = "nullable")]
    pub protocol_version: String,
    /// The agent's name.
    #[serde(deserialize_with = "nullable")]
    pub name: String,
    /// The agent's description.
    #[serde(deserialize_with = "nullable")]
    pub description: String,
    /// The agent's version.
    #[serde(deserialize_with = "nullable")]
    pub version: String,
    /// Who provides the agent.
    #[serde(deserialize_with = "nullable")]
    pub provider: AgentProvider,
    /// The bindings the agent is reachable on, preferred first.
    #[serde(deserialize_with = "nullable")]
    pub supported_interfaces: Vec<AgentInterface>,
    /// The MIME modes it accepts by default.
    #[serde(deserialize_with = "nullable")]
    pub default_input_modes: Vec<String>,
    /// The MIME modes it produces by default.
    #[serde(deserialize_with = "nullable")]
    pub default_output_modes: Vec<String>,
    /// The optional protocol features it claims.
    #[serde(deserialize_with = "nullable")]
    pub capabilities: AgentCapabilities,
    /// The skills it declares.
    #[serde(deserialize_with = "nullable")]
    pub skills: Vec<AgentSkill>,
    /// The security schemes, verbatim.
    #[serde(deserialize_with = "nullable")]
    pub security_schemes: BTreeMap<String, Value>,
    /// The scheme names a caller must satisfy.
    #[serde(deserialize_with = "nullable")]
    pub security: Vec<BTreeMap<String, Vec<String>>>,
    /// The JWS signatures over the card.
    #[serde(deserialize_with = "nullable")]
    pub signatures: Vec<AgentCardSignature>,
}

/// A member that may be `null`: `null` reads as the member's default, as if it were absent.
fn nullable<'de, D, T>(de: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Option::<T>::deserialize(de).map(Option::unwrap_or_default)
}

/// Read the members busbar acts on; `None` when the document is not a card (not an object, or a member present with the wrong type; a `null` member is absent).
#[must_use]
pub fn parse(card: &Value) -> Option<AgentCard> {
    if !card.is_object() {
        return None;
    }
    AgentCard::deserialize(card).ok()
}

/// Validate the required interface declaration before selecting a transport. Protocol versions
/// are explicit on every interface; a missing declaration is not a version negotiation.
pub fn validate_interfaces(card: &Value) -> Result<(), &'static str> {
    let interfaces = card
        .get("supportedInterfaces")
        .and_then(Value::as_array)
        .ok_or("agent card supportedInterfaces must be an array")?;
    if interfaces.is_empty() {
        return Err("agent card supportedInterfaces must declare at least one interface");
    }
    for interface in interfaces {
        for field in ["url", "protocolBinding", "protocolVersion"] {
            if !interface.get(field).is_some_and(Value::is_string) {
                return Err(
                    "agent card interface requires string url, protocolBinding and protocolVersion",
                );
            }
        }
    }
    Ok(())
}

/// Validate the required A2A v1.0.1 card fields before trust or skill approval can be recorded.
/// This is separate from `parse`, the partial projection used to inspect stored documents.
/// It validates required fields in the modeled discovery objects, not the complete protocol
/// schema: open security-scheme bodies and extension semantics remain outside this projection.
pub fn validate(card: &Value) -> Result<(), &'static str> {
    for field in ["name", "description", "version"] {
        if !card.get(field).is_some_and(Value::is_string) {
            return Err("agent card requires string name, description and version");
        }
    }
    validate_interfaces(card)?;
    if !card.get("capabilities").is_some_and(Value::is_object) {
        return Err("agent card capabilities must be an object");
    }
    for field in ["defaultInputModes", "defaultOutputModes"] {
        if !card
            .get(field)
            .and_then(Value::as_array)
            .is_some_and(|values| !values.is_empty() && values.iter().all(Value::is_string))
        {
            return Err("agent card default input and output modes must be string arrays");
        }
    }
    let skills = card
        .get("skills")
        .and_then(Value::as_array)
        .ok_or("agent card skills must be an array")?;
    if skills.is_empty() {
        return Err("agent card skills must contain at least one skill");
    }
    for skill in skills {
        for field in ["id", "name", "description"] {
            if !skill.get(field).is_some_and(Value::is_string) {
                return Err("agent card skills require string id, name and description");
            }
        }
        if !skill
            .get("tags")
            .and_then(Value::as_array)
            .is_some_and(|tags| !tags.is_empty() && tags.iter().all(Value::is_string))
        {
            return Err("agent card skill tags must be a string array");
        }
    }
    if let Some(provider) = card.get("provider").filter(|value| !value.is_null()) {
        for field in ["url", "organization"] {
            if !provider.get(field).is_some_and(Value::is_string) {
                return Err("agent card provider requires string url and organization");
            }
        }
    }
    if let Some(signatures) = card.get("signatures").filter(|value| !value.is_null()) {
        let signatures = signatures
            .as_array()
            .ok_or("agent card signatures must be an array")?;
        for signature in signatures {
            for field in ["protected", "signature"] {
                if !signature.get(field).is_some_and(Value::is_string) {
                    return Err("agent card signatures require string protected and signature");
                }
            }
        }
    }
    if parse(card).is_none() {
        return Err("agent card contains a malformed field");
    }
    Ok(())
}
