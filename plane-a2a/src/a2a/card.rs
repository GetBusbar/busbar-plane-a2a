// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The two hashes taken over an agent card, and the per-skill digests. The plane computes them and

use std::collections::BTreeMap;

use busbar_contract::abi::sdk::digest::sha256_tagged;
use serde_json::Value;

use super::canonical::{canonicalize, CanonicalError};

/// What went wrong reading or hashing a card. Each arm is a case where continuing would produce an
/// approval an operator could not reason about.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CardError {
    /// The document is not a JSON object, so it is not a card at all.
    NotAnObject,
    /// A present skill set is neither the proto default nor an array of skills.
    InvalidSkills,
    /// The document cannot be canonicalized, so no reproducible hash exists for it.
    Canonical(CanonicalError),
    /// A skill carries no `id`, so there is nothing for an operator to approve it BY. An index would
    /// be worse than an error: re-ordering the array would silently move every approval.
    SkillWithoutId,
    /// Two skills share one `id`. Whichever won would decide what "approved `plan` at this digest"
    /// meant, so the ambiguity is refused rather than resolved.
    DuplicateSkillId(String),
}

impl std::fmt::Display for CardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CardError::NotAnObject => write!(f, "agent card is not a JSON object"),
            CardError::InvalidSkills => write!(f, "agent card skills must be an array"),
            CardError::Canonical(e) => write!(f, "agent card cannot be canonicalized: {e}"),
            CardError::SkillWithoutId => {
                write!(
                    f,
                    "agent card declares a skill with no `id` to approve it by"
                )
            }
            CardError::DuplicateSkillId(id) => write!(
                f,
                "agent card declares the skill id `{id}` twice; which one an approval refers to is \
                 ambiguous"
            ),
        }
    }
}

impl From<CanonicalError> for CardError {
    fn from(e: CanonicalError) -> Self {
        CardError::Canonical(e)
    }
}

/// THE PINNED FINGERPRINT: a hash of the canonical WHOLE card, signatures included.
pub fn fingerprint(card: &Value) -> Result<String, CardError> {
    if !card.is_object() {
        return Err(CardError::NotAnObject);
    }
    Ok(sha256_tagged(canonicalize(card)?.as_bytes()))
}

/// THE JWS PAYLOAD: the canonical card with `signatures` removed, because a signature cannot cover
pub fn signing_payload(card: &Value) -> Result<String, CardError> {
    let mut stripped = card.clone();
    let obj = stripped.as_object_mut().ok_or(CardError::NotAnObject)?;
    obj.remove("signatures");
    if obj.get("supportedInterfaces").is_some_and(Value::is_array) {
        omit_defaults(&mut stripped, CARD);
    }
    Ok(canonicalize(&stripped)?)
}

/// How one member of an agent card's messages reads under proto3 field presence (A2A v1.0 §5.7),
/// by its ProtoJSON name. A member a message's table does not name is `REQUIRED`, `optional`, or
/// not declared, and is kept as it is.
#[derive(Clone, Copy)]
enum Member {
    /// Implicit presence (neither `REQUIRED` nor `optional`): omitted at its default (`""`,
    /// `false`, `0`, `[]`, `{}`).
    Implicit,
    /// A repeated message field, each entry that message; omitted when empty unless `REQUIRED`
    /// (`true`).
    List(Message, bool),
    /// A map whose values are that message: omitted when empty.
    Map(Message),
    /// A singular message field (explicit presence): kept when present, read inside.
    Of(Message),
}

/// One proto message of the card: its members that are not simply kept.
type Message = &'static [(&'static str, Member)];

/// `AgentCard` (`signatures` is removed before this is read).
const CARD: Message = &[
    ("supportedInterfaces", Member::List(INTERFACE, true)),
    ("capabilities", Member::Of(CAPABILITIES)),
    ("securitySchemes", Member::Map(SCHEME)),
    ("securityRequirements", Member::List(REQUIREMENT, false)),
    ("skills", Member::List(SKILL, true)),
];
/// `AgentInterface`.
const INTERFACE: Message = &[("tenant", Member::Implicit)];
/// `AgentCapabilities` (`streaming`, `pushNotifications`, `extendedAgentCard` are `optional`).
const CAPABILITIES: Message = &[("extensions", Member::List(EXTENSION, false))];
/// `AgentExtension` (`params` is a `Struct`, a message: kept when present).
const EXTENSION: Message = &[
    ("uri", Member::Implicit),
    ("description", Member::Implicit),
    ("required", Member::Implicit),
];
/// `AgentSkill`.
const SKILL: Message = &[
    ("examples", Member::Implicit),
    ("inputModes", Member::Implicit),
    ("outputModes", Member::Implicit),
    ("securityRequirements", Member::List(REQUIREMENT, false)),
];
/// `SecurityRequirement`.
const REQUIREMENT: Message = &[("schemes", Member::Map(STRING_LIST))];
/// `StringList`.
const STRING_LIST: Message = &[("list", Member::Implicit)];
/// `SecurityScheme` (a oneof of messages).
const SCHEME: Message = &[
    ("apiKeySecurityScheme", Member::Of(DESCRIBED)),
    ("httpAuthSecurityScheme", Member::Of(HTTP_AUTH)),
    ("oauth2SecurityScheme", Member::Of(OAUTH2)),
    ("openIdConnectSecurityScheme", Member::Of(DESCRIBED)),
    ("mtlsSecurityScheme", Member::Of(DESCRIBED)),
];
/// `APIKeySecurityScheme`, `OpenIdConnectSecurityScheme`, `MutualTlsSecurityScheme`: only
const DESCRIBED: Message = &[("description", Member::Implicit)];
/// `HTTPAuthSecurityScheme`.
const HTTP_AUTH: Message = &[
    ("description", Member::Implicit),
    ("bearerFormat", Member::Implicit),
];
/// `OAuth2SecurityScheme`.
const OAUTH2: Message = &[
    ("description", Member::Implicit),
    ("flows", Member::Of(FLOWS)),
    ("oauth2MetadataUrl", Member::Implicit),
];
/// `OAuthFlows` (a oneof of messages).
const FLOWS: Message = &[
    ("authorizationCode", Member::Of(AUTHORIZATION_CODE)),
    ("clientCredentials", Member::Of(REFRESHED)),
    ("implicit", Member::Of(IMPLICIT_FLOW)),
    ("password", Member::Of(PASSWORD_FLOW)),
    ("deviceCode", Member::Of(REFRESHED)),
];
/// `AuthorizationCodeOAuthFlow`.
const AUTHORIZATION_CODE: Message = &[
    ("refreshUrl", Member::Implicit),
    ("pkceRequired", Member::Implicit),
];
/// `ClientCredentialsOAuthFlow`, `DeviceCodeOAuthFlow`: only `refreshUrl` is implicit.
const REFRESHED: Message = &[("refreshUrl", Member::Implicit)];
/// `ImplicitOAuthFlow` (no member is `REQUIRED`).
const IMPLICIT_FLOW: Message = &[
    ("authorizationUrl", Member::Implicit),
    ("refreshUrl", Member::Implicit),
    ("scopes", Member::Implicit),
];
/// `PasswordOAuthFlow` (no member is `REQUIRED`).
const PASSWORD_FLOW: Message = &[
    ("tokenUrl", Member::Implicit),
    ("refreshUrl", Member::Implicit),
    ("scopes", Member::Implicit),
];

/// Whether `v` is a proto default as ProtoJSON writes one.
fn is_default(v: &Value) -> bool {
    match v {
        Value::String(s) => s.is_empty(),
        Value::Bool(b) => !b,
        Value::Number(n) => n.as_f64() == Some(0.0),
        Value::Array(a) => a.is_empty(),
        Value::Object(o) => o.is_empty(),
        Value::Null => false,
    }
}

/// Omit `v`'s default-valued implicit members, as `message` declares them, at every depth.
fn omit_defaults(v: &mut Value, message: Message) {
    let Some(obj) = v.as_object_mut() else {
        return;
    };
    for (name, member) in message {
        let Some(value) = obj.get_mut(*name) else {
            continue;
        };
        let omit = match member {
            Member::Implicit => is_default(value),
            Member::List(inner, required) => {
                if let Value::Array(entries) = value {
                    entries.iter_mut().for_each(|e| omit_defaults(e, inner));
                }
                !required && is_default(value)
            }
            Member::Map(inner) => {
                if let Value::Object(entries) = value {
                    entries.values_mut().for_each(|e| omit_defaults(e, inner));
                }
                is_default(value)
            }
            Member::Of(inner) => {
                omit_defaults(value, inner);
                false
            }
        };
        if omit {
            obj.remove(*name);
        }
    }
}

/// The capability set the plane-neutral machine compares: skill id to a digest of that skill's
pub fn skill_digests(card: &Value) -> Result<BTreeMap<String, String>, CardError> {
    let skills = match card
        .as_object()
        .ok_or(CardError::NotAnObject)?
        .get("skills")
    {
        None | Some(Value::Null) => &[][..],
        Some(Value::Array(skills)) => skills.as_slice(),
        Some(_) => return Err(CardError::InvalidSkills),
    };
    let mut out = BTreeMap::new();
    for skill in skills {
        let id = skill
            .get("id")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or(CardError::SkillWithoutId)?;
        let digest = sha256_tagged(canonicalize(skill)?.as_bytes());
        if out.insert(id.to_string(), digest).is_some() {
            return Err(CardError::DuplicateSkillId(id.to_string()));
        }
    }
    Ok(out)
}

#[cfg(test)]
#[path = "tests/card_tests.rs"]
mod tests;
