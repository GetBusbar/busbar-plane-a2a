// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `agents:` SECTION — the A2A plane's config grammar, and the one place its values are judged.

use busbar_contract::section::split_section;
use serde::{Deserialize, Serialize};

/// The default MAX VERIFICATION STALENESS for a registration that names none: five seconds.
pub const DEFAULT_REVERIFY_TTL: &str = "5s";

/// WHAT ONE `agents:` ENTRY IS CALLED in the section's refusals and in the plane's declaration.
pub const SUBJECT_NOUN: &str = "fronted agent";

/// THE REFUSAL FOR `upstream_credentials: passthrough` ON THIS PLANE, written once so the per-entry and section-level paths cannot say different things about the same rule.
pub const REFUSE_PASSTHROUGH_SECTION: &str =
    "`upstream_credentials: passthrough` is refused on the `agents:` plane. busbar delegates AS \
     ITSELF: the caller's key authenticated them to busbar and means nothing to a third-party \
     agent, so forwarding it would hand that agent a working busbar credential belonging to \
     someone else. Use `own` with an `upstream_credential:` handle.";

/// `agents.<name>.pin.mechanism` — WHICH authenticity root this registration has.
///
/// The variants are the four the design names, and they are spelled in config exactly as the card
/// pin renders them, so an operator comparing a config file against
/// an admin response or an audit row is comparing the same strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PinMechanism {
    /// The card is SIGNED and verified against an operator-supplied, out-of-band JWS issuer key.
    JwsIssuerKey,
    /// The card is UNSIGNED; authenticity is bound to the card endpoint's certificate SPKI hash.
    #[serde(rename = "cert_spki")]
    CertKeyPin,
    /// The card is UNSIGNED and served behind mutual TLS; pinned on the peer certificate SPKI hash.
    #[serde(rename = "mtls")]
    MutualTls,
    /// NO authenticity root. Registrable, never approvable.
    Unpinned,
}

impl PinMechanism {
    /// The config token, for diagnostics, pin renderings and audit rows.
    pub fn token(self) -> &'static str {
        match self {
            PinMechanism::JwsIssuerKey => "jws_issuer_key",
            PinMechanism::CertKeyPin => "cert_spki",
            PinMechanism::MutualTls => "mtls",
            PinMechanism::Unpinned => "unpinned",
        }
    }
}

/// `agents.<name>.client_identity` — THE CERTIFICATE BUSBAR PRESENTS to this agent's endpoint.
///
/// ## Why this is a sibling of `pin:` and not a field inside it
///
/// `pin:` answers "how do I know this card is the vendor's". This answers "how does the vendor know
/// this connection is busbar's". They are opposite directions of the same handshake and only one of
/// them is a trust root, so folding busbar's own key material into the object whose documented job
/// is "the operator-supplied trust root" would make `pin:` mean two things.
///
/// ## The two fields are SECRET REFERENCES, exactly as `tls:` spells them
///
/// `cert:` and `key:` are [`busbar_contract::secret_ref::SecretRef`]s — `{module, settings}` with the `env` / `file`
/// sugar — which is the CLEAN-CONFIG rule the whole config surface already obeys and the same
/// spelling `tls.cert:` / `tls.key:` use for busbar's INBOUND identity. There is deliberately no way
/// to write PEM bytes here: a private key inlined in config is a private key in every config dump,
/// every `--validate` output, every admin GET and every version-history row. Reusing `SecretRef`
/// rather than inventing a path field also means this material resolves through the ONE resolver
/// (`env`/`file` built in, any `kind: secret` plugin beyond that), so a deployment that keeps its
/// keys in Vault keeps this one there too without busbar learning a second way to fetch a key.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClientIdentityCfg {
    /// PEM certificate chain busbar presents, leaf first. Public material, still a reference:
    /// operators keep a chain and its key in the same place, and splitting the spelling would be an
    /// invitation to inline the other one.
    pub cert: busbar_contract::secret_ref::SecretRef,
    /// PEM private key for `cert:` — PKCS#8, PKCS#1 or SEC1. NEVER the key itself.
    pub key: busbar_contract::secret_ref::SecretRef,
}

/// `agents.<name>.pin` — the out-of-band operator-supplied trust root.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentPinCfg {
    /// Which root this is. Required: a pin whose mechanism is inferred is a pin whose meaning
    /// changes when the code that infers it changes.
    pub mechanism: PinMechanism,
    /// The operator-supplied material: a JWS verification key, or a certificate SPKI hash. Absent
    /// only for `unpinned`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// The approved canonical card fingerprint, where the operator already has one. Absent means
    /// "capture it at `connect` and let me approve it", which is the normal first registration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
}

/// One entry in the top-level `agents:` NAMED-DEFINITION map — one registered external A2A agent.
///
/// Operator INTENT only. Everything that ACCUMULATES about an agent — every observed card, the
/// drift queue, the approval trail, the anomaly counters, the task rows — is store state and is
/// deliberately absent from this struct. The split is not tidiness: intent is what an operator
/// wrote and may edit, accumulation is what happened and may not be, and a field that lives in the
/// wrong one is a field an admin write can silently rewrite history through.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentDefCfg {
    /// The real remote A2A endpoint. Never client-visible: callers reach it through busbar.
    pub url: String,
    /// The out-of-band trust root. REQUIRED, and required to be spelled even when it is
    /// `unpinned` — see the module note on why absence is not an acceptable spelling for "none".
    pub pin: AgentPinCfg,
    /// THE CLIENT CERTIFICATE BUSBAR PRESENTS ON THE HOP TO THIS AGENT. Required when
    /// `pin.mechanism: mtls` — that mechanism means "this endpoint is served behind mutual TLS", and
    /// a registration that says so with nothing to present cannot complete a handshake. Legal, and
    /// optional, under the other mechanisms: a vendor may demand a client certificate whatever it
    /// does about signing its card.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_identity: Option<ClientIdentityCfg>,
    /// `<n><s|m|h|d>` — the LONGEST a verification may be reused on the delegation path before the
    /// card is re-fetched and re-verified. Absent ⇒ [`DEFAULT_REVERIFY_TTL`] (`5s`); `0` is strict-live.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reverify_ttl: Option<String>,
    /// How long after a DRIFT a clean answer is disbelieved. Absent ⇒ the deployment default.
    ///
    /// This is the recovery backoff, and it is the only half of the cadence that is ever held.
    /// There is deliberately no knob that slows DETECTION or delays a DEMOTION: both would be a
    /// window an upstream could open for itself by flapping, and choosing when to flap is entirely
    /// within its gift.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_backoff: Option<String>,
    /// MAY THIS AGENT LIVE ON A PRIVATE OR LOOPBACK ADDRESS, AND BE REACHED OVER PLAINTEXT.
    ///
    /// The SAME spelling, the same semantics and the same fail-closed default as the MCP plane's
    /// `allow_private`, deliberately, because the two are one
    /// operator concept and an operator who has learned it on `tools:` must not have to learn it
    /// again here. What it permits, exactly as on the sibling plane:
    ///
    /// - a plaintext `http://` card endpoint, and
    /// - a host that resolves to a loopback, link-local, RFC1918 or CGNAT address.
    ///
    /// WHAT IT NEVER PERMITS, and this is the half that makes the knob safe to have: a
    /// CLOUD-METADATA endpoint. `169.254.169.254` and its family are refused whether this is set or
    /// not, by the host's destination guard: an `allow_private` that reached IMDS would be a configuration flag that hands out cloud
    /// credentials.
    ///
    /// Default FALSE. A hermetic rig, a laptop and a sidecar are real deployments, and every one of
    /// them is also what an SSRF looks like from inside the process — so it is the operator saying
    /// it out loud, per registration, or it does not happen.
    #[serde(default)]
    pub allow_private: bool,
    /// Outbound credential mode at delegation time. Same vocabulary as the pool plane's — and
    /// `passthrough` is REFUSED here, loudly, by [`validate_agent`]. The word is reserved on every
    /// plane so the vocabulary is learned once; a plane that cannot honor a VALUE says so rather
    /// than accepting it and doing something else.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_credentials: Option<busbar_contract::config::UpstreamCreds>,
    /// The LEASED outbound credential busbar presents to this agent: a secret-store handle
    /// plus its lease policy. Never the secret, never the caller's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_credential: Option<super::creds::OutboundCredential>,
    /// Which fronted agents may delegate here (the egress policy). Nothing in this build enforces
    /// the list, so [`validate_agent`] refuses a non-empty one. Retained in the grammar so the
    /// refusal names the unsupported control instead of calling the key unknown.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub egress_scopes: Vec<String>,
    /// Hooks attached to THIS agent, by bare name from the top-level `hooks:` map. ADDS to the
    /// section-level `agents.hooks:` list.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hooks: Vec<String>,
}

/// The top-level `agents:` map, carrying the two `RESERVED_SECTION_KEYS`
/// alongside the agents.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AgentsCfg {
    /// The ALL-AGENTS attach list (the reserved `agents.hooks:` key). LIST ⇒ ADDITIVE: an agent's
    /// own `hooks:` are appended to this, deduped by name.
    pub all_agent_hooks: Vec<String>,
    /// The ALL-AGENTS `upstream_credentials:` default. SCALAR ⇒ OVERRIDE.
    pub all_agent_upstream_credentials: Option<busbar_contract::config::UpstreamCreds>,
    /// The registrations. Insertion-ordered, so catalogue construction and every operator-facing
    /// listing are deterministic rather than hash-ordered.
    pub agents: indexmap::IndexMap<String, AgentDefCfg>,
    /// THE FAILOVER POOLS the host hands the section at its reserved `pools` key (the neutral
    /// top-level `pools:` whose members are `agents:` registrations): each pool's members, in the
    /// order declared, the first the primary. Lifted off the section before it is read
    /// ([`crate::statement::read_agents_section`]); empty when it states none.
    pub pools: indexmap::IndexMap<String, Vec<String>>,
}

impl AgentsCfg {
    /// The pool `agent` is a member of, by name, and its members in declared order: the first pool naming it, in the order the section states them.
    #[must_use]
    pub fn pool_of(&self, agent: &str) -> Option<(&str, &[String])> {
        self.pools
            .iter()
            .find(|(_, members)| members.iter().any(|m| m == agent))
            .map(|(name, members)| (name.as_str(), members.as_slice()))
    }
}

impl<'de> Deserialize<'de> for AgentsCfg {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let section = split_section::<D, AgentDefCfg>(
            deserializer,
            crate::CONFIG_SECTION,
            SUBJECT_NOUN,
            validate_agent,
        )?;

        if section.upstream_credentials == Some(busbar_contract::config::UpstreamCreds::Passthrough)
        {
            return Err(serde::de::Error::custom(REFUSE_PASSTHROUGH_SECTION));
        }

        Ok(AgentsCfg {
            all_agent_hooks: section.hooks,
            all_agent_upstream_credentials: section.upstream_credentials,
            agents: section.entries,
            pools: indexmap::IndexMap::new(),
        })
    }
}

/// `url` as a refusal may repeat it: any userinfo in its authority (everything before the last `@`
/// ahead of the path, found where the URL reader finds it) replaced by `***`; a malformed URL, or one
/// whose userinfo cannot be located in the raw spelling, is omitted entirely.
#[must_use]
pub fn without_userinfo(url: &str) -> std::borrow::Cow<'_, str> {
    let Ok(parts) = busbar_contract::net::parse_url(url) else {
        return std::borrow::Cow::Borrowed("<malformed URL omitted>");
    };
    let after_scheme = url.find(':').map_or(0, |i| i + 1);
    let rest = &url[after_scheme..];
    let start = after_scheme
        + match parts.family {
            busbar_contract::net::UrlFamily::Web => {
                rest.len() - rest.trim_start_matches(['/', '\\']).len()
            }
            busbar_contract::net::UrlFamily::Generic => {
                if rest.starts_with("//") {
                    2
                } else {
                    0
                }
            }
        };
    let authority_end = url[start..]
        .find(['/', '?', '#'])
        .map_or(url.len(), |i| start + i);
    match url[start..authority_end].rfind('@') {
        Some(at) => std::borrow::Cow::Owned(format!("{}***{}", &url[..start], &url[start + at..])),
        None if parts.userinfo => std::borrow::Cow::Borrowed("<URL with userinfo omitted>"),
        None => std::borrow::Cow::Borrowed(url),
    }
}

/// THE VALUE-LEVEL RULES for one `agents:` entry.
pub fn validate_agent(name: &str, def: &AgentDefCfg) -> Result<(), String> {
    let at = format!("`agents.{name}`");

    if crate::statement::agent_claim_count([name]) == 0 {
        return Err(format!(
            "{at}: an agent name must be one plain path segment (letters, digits, `-`, `_`, `.`, \
             `~`; not `.` or `..`): it names the agent's `/a2a/agents/<name>/` endpoint"
        ));
    }

    if def.url.trim().is_empty() {
        return Err(format!("{at}: `url:` must name the agent's A2A endpoint"));
    }

    let parsed = busbar_contract::net::parse_url(&def.url);
    let scheme_ok = def.url.split_once("://").is_some_and(|(scheme, _)| {
        scheme.eq_ignore_ascii_case("https") || scheme.eq_ignore_ascii_case("http")
    });
    if !scheme_ok
        || parsed
            .as_ref()
            .is_ok_and(|p| p.scheme != "https" && p.scheme != "http")
    {
        return Err(format!(
            "{at}: `url:` must be an http:// or https:// endpoint, got `{}`",
            without_userinfo(&def.url)
        ));
    }
    if let Err(why) = parsed.as_ref() {
        return Err(format!(
            "{at}: `url:` is malformed ({why}); the supplied URL is omitted"
        ));
    }
    if parsed.as_ref().is_ok_and(|p| p.userinfo) {
        return Err(format!(
            "{at}: `url:` carries a userinfo (`user@` or `user:password@`) in its authority; name \
             the agent's credential under `upstream_credential:`, never in its URL"
        ));
    }

    if def.pin.mechanism == PinMechanism::MutualTls && def.client_identity.is_none() {
        return Err(format!(
            "{at}: `pin.mechanism: mtls` needs `client_identity:` — the `cert:` and `key:` \
             references to the certificate busbar PRESENTS to this endpoint. `mtls` means the \
             endpoint is served behind mutual TLS, and a client with nothing to present is refused \
             at the handshake with `CertificateRequired`, not at the pin."
        ));
    }

    if def.client_identity.is_some() && parsed.as_ref().is_ok_and(|p| p.scheme == "http") {
        return Err(format!(
            "{at}: `client_identity:` is a TLS client certificate and `url:` is `http://`, which \
             has no handshake to present it in. Name an `https://` endpoint, or drop the identity."
        ));
    }

    if def.upstream_credentials == Some(busbar_contract::config::UpstreamCreds::Passthrough) {
        return Err(format!("{at}: {REFUSE_PASSTHROUGH_SECTION}"));
    }
    if let Some(cred) = def.upstream_credential.as_ref() {
        if cred.lease_ttl_ms == 0 {
            return Err(format!(
                "{at}: `upstream_credential.lease_ttl_ms:` must be greater than zero. A lease that \
                 expires at the instant it is minted is a credential that can never be presented."
            ));
        }
        if let super::creds::CredentialPlacement::Header(name) = &cred.placement {
            if name.trim().is_empty() {
                return Err(format!(
                    "{at}: `upstream_credential.placement.header:` must name a header"
                ));
            }
        }
    }

    if !def.egress_scopes.is_empty() {
        return Err(format!(
            "{at}: `egress_scopes:` is not enforced by this build; remove it"
        ));
    }

    Ok(())
}

#[cfg(test)]
#[path = "tests/config_tests.rs"]
pub(crate) mod tests;
