// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The skill a request matches on an agent's card: busbar's own namespaced annotation,
//! `metadata["busbar/skill"]` on the answer.
//!
//! The fit is STRUCTURAL, never a score: an agent either can accept this shape of task or it
//! cannot. A request that names a skill matches the card's skill of that id under the skill's own
//! modes (the card's defaults where it declares none); one that names none matches no skill.

use serde_json::Value;

use crate::a2a::agent_card::AgentCard;

/// EVERY PLACE A2A SPELLS the push-callback config object, in both revisions: v0.3's
/// `pushNotificationConfig`, v1.0's `taskPushNotificationConfig`, flat or nested. The URL and the
/// credential beside it are read out of ONE object.
pub const CALLBACK_CONFIG_POINTERS: [&str; 3] = [
    "/params/configuration/pushNotificationConfig",
    "/params/configuration/taskPushNotificationConfig",
    "/params/configuration/taskPushNotificationConfig/pushNotificationConfig",
];

/// DOES THIS METHOD NAME ASK FOR A STREAM? Both eras of the name: v0.3's `message/stream` and
/// `tasks/resubscribe`, v1.0's `SendStreamingMessage` and `SubscribeToTask`.
#[must_use]
pub fn reads_as_stream(method: &str) -> bool {
    method.ends_with("/stream")
        || method == "tasks/resubscribe"
        || method == "SendStreamingMessage"
        || method == "SubscribeToTask"
}

/// THE SHAPE OF A TASK, as the fit is allowed to see it: typed metadata only, never prose.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TaskShape {
    /// The skill being asked for, by `id`. `None` means "any skill this agent declares".
    pub skill: Option<String>,
    /// The task needs a stream.
    pub requires_stream: bool,
    /// The task registers a push callback.
    pub requires_push_notifications: bool,
    /// MIME modes the caller can ACCEPT back (`configuration.acceptedOutputModes`). A request
    /// states no modes it will send, so the fit reads only this side.
    pub output_modes: Vec<String>,
}

impl TaskShape {
    /// The shape an inbound envelope asks for. An envelope that names nothing constrains nothing.
    #[must_use]
    pub fn of(envelope: &Value) -> Self {
        let params = envelope.get("params");
        let cfg = params.and_then(|p| p.get("configuration"));
        TaskShape {
            skill: params
                .and_then(|p| p.get("metadata"))
                .and_then(|m| m.get("skill"))
                .and_then(Value::as_str)
                .map(str::to_string),
            requires_stream: envelope
                .get("method")
                .and_then(Value::as_str)
                .is_some_and(reads_as_stream),
            requires_push_notifications: CALLBACK_CONFIG_POINTERS
                .into_iter()
                .any(|p| envelope.pointer(p).is_some_and(Value::is_object)),
            output_modes: cfg
                .and_then(|c| c.get("acceptedOutputModes"))
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default(),
        }
    }
}

/// Why a card does not fit a shape; [`Unfit::words`] is the sentence its refusal carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Unfit {
    /// The card declares no skill with the requested id.
    SkillNotDeclared(String),
    /// The card does not declare a capability the task requires.
    CapabilityNotDeclared(&'static str),
    /// The card produces none of the modes the caller accepts.
    ModesIncompatible,
    /// The held card cannot be read.
    Unreadable(Unreadable),
    /// No card is held for the agent: nothing to judge the request's shape against.
    NoCachedCard,
}

impl Unfit {
    /// The caller's sentence for this exclusion (a skill id is the caller's own word, bounded).
    #[must_use]
    pub fn words(&self) -> String {
        match self {
            Unfit::SkillNotDeclared(skill) => format!(
                "this agent's card declares no skill `{}`",
                crate::binding::bounded_word(skill)
            ),
            Unfit::CapabilityNotDeclared(capability) => format!(
                "this agent's card does not declare the `{capability}` capability this request needs"
            ),
            Unfit::ModesIncompatible => "this agent's card produces none of the output modes \
                                         this request accepts in `acceptedOutputModes`"
                .to_string(),
            Unfit::Unreadable(Unreadable::NotAnObject) => {
                "this agent's held card cannot be read: it is not a JSON object".to_string()
            }
            Unfit::NoCachedCard => "busbar holds no card for this agent yet, so the request \
                                    cannot be judged against what the agent declares"
                .to_string(),
        }
    }
}

/// Why a held card cannot be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unreadable {
    /// The document is not a card.
    NotAnObject,
}

/// THE FIT of a held card DOCUMENT to `shape`: [`judge`] over the card read.
///
/// # Errors
/// [`Unfit`]; [`Unfit::Unreadable`] for a document that is not a card.
pub fn fit(card: &Value, shape: &TaskShape) -> Result<Option<String>, Unfit> {
    let card =
        crate::a2a::agent_card::parse(card).ok_or(Unfit::Unreadable(Unreadable::NotAnObject))?;
    judge(&card, shape)
}

/// The status a request an agent's card does not fit is refused with.
pub const STATUS_UNFIT: u32 = 403;

/// The refusal of a request an agent's held card does not fit:
/// `403`, `-32004`, no id, the exclusion's sentence ([`Unfit::words`]) as the message.
#[must_use]
pub fn refusal(unfit: &Unfit) -> crate::agent_arrival::AgentRefusal {
    crate::agent_arrival::AgentRefusal::new(
        STATUS_UNFIT,
        None,
        crate::agent_arrival::CODE_UNSUPPORTED_OPERATION,
        unfit.words(),
    )
}

/// JUDGE WHETHER AN AGENT CARD FITS A TASK SHAPE: the matched skill id (`None` when the shape
/// names none), or why it does not fit.
///
/// # Errors
/// [`Unfit`].
pub fn judge(card: &AgentCard, shape: &TaskShape) -> Result<Option<String>, Unfit> {
    if shape.requires_stream && !card.capabilities.is_stream {
        return Err(Unfit::CapabilityNotDeclared("streaming"));
    }
    if shape.requires_push_notifications && !card.capabilities.push_notifications {
        return Err(Unfit::CapabilityNotDeclared("pushNotifications"));
    }
    if let Some(wanted) = &shape.skill {
        let skill = card
            .skills
            .iter()
            .find(|s| &s.id == wanted)
            .ok_or_else(|| Unfit::SkillNotDeclared(wanted.clone()))?;
        // A skill's own modes OVERRIDE the card defaults where it declares them.
        check_modes(shape, pick(&skill.output_modes, &card.default_output_modes))?;
        return Ok(Some(skill.id.clone()));
    }
    check_modes(shape, &card.default_output_modes)?;
    Ok(None)
}

fn pick<'a>(specific: &'a [String], fallback: &'a [String]) -> &'a [String] {
    if specific.is_empty() {
        fallback
    } else {
        specific
    }
}

/// The caller must be able to RECEIVE something the agent produces; a side that names no modes
/// constrains nothing.
fn check_modes(shape: &TaskShape, agent_outputs: &[String]) -> Result<(), Unfit> {
    let wanted = &shape.output_modes;
    if wanted.is_empty()
        || agent_outputs.is_empty()
        || wanted.iter().any(|w| agent_outputs.contains(w))
    {
        Ok(())
    } else {
        Err(Unfit::ModesIncompatible)
    }
}

#[cfg(test)]
#[path = "tests/skill_tests.rs"]
mod tests;
