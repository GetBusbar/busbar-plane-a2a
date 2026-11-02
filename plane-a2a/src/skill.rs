// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The skill a request matches on an agent's card: busbar's own namespaced annotation,

use serde_json::Value;

use crate::a2a::agent_card::AgentCard;

/// EVERY PLACE A2A SPELLS the push-callback config object, in both revisions: v0.3's
pub const CALLBACK_CONFIG_POINTERS: [&str; 8] = [
    "/params/configuration/pushNotificationConfig",
    "/params/configuration/push_notification_config",
    "/params/configuration/taskPushNotificationConfig/pushNotificationConfig",
    "/params/configuration/taskPushNotificationConfig/push_notification_config",
    "/params/configuration/task_push_notification_config/pushNotificationConfig",
    "/params/configuration/task_push_notification_config/push_notification_config",
    "/params/configuration/taskPushNotificationConfig",
    "/params/configuration/task_push_notification_config",
];

/// DOES THIS METHOD NAME ASK FOR A STREAM? Both eras of the name: v0.3's `message/stream` and
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
    /// The shape an inbound envelope asks for. Send requests have their field types checked at
    #[must_use]
    pub fn of(envelope: &Value) -> Self {
        let params = envelope.get("params");
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
            output_modes: requested_output_modes(envelope)
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

fn requested_output_modes(envelope: &Value) -> Option<&Value> {
    let configuration = envelope.get("params")?.get("configuration")?;
    configuration
        .get("acceptedOutputModes")
        .or_else(|| configuration.get("accepted_output_modes"))
}

/// Validate the request fields that structural fit reads, before a send request is routed.
pub(crate) fn validate_fields(envelope: &Value) -> Result<(), &'static str> {
    if envelope
        .pointer("/params/metadata/skill")
        .is_some_and(|skill| !skill.is_null() && !skill.is_string())
    {
        return Err("params.metadata.skill must be a string");
    }
    if requested_output_modes(envelope).is_some_and(|modes| {
        !modes.is_null()
            && modes
                .as_array()
                .is_none_or(|modes| modes.iter().any(|mode| !mode.is_string()))
    }) {
        return Err("params.configuration.acceptedOutputModes must be an array of strings");
    }
    Ok(())
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
pub fn fit(card: &Value, shape: &TaskShape) -> Result<Option<String>, Unfit> {
    let card =
        crate::a2a::agent_card::parse(card).ok_or(Unfit::Unreadable(Unreadable::NotAnObject))?;
    judge(&card, shape)
}

/// The HTTP status of the unsupported-operation refusal when an agent's card does not fit.
pub const STATUS_UNFIT: u32 = 400;

/// The refusal of a request an agent's held card does not fit:
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
fn check_modes(shape: &TaskShape, agent_outputs: &[String]) -> Result<(), Unfit> {
    let wanted = &shape.output_modes;
    if wanted.is_empty()
        || agent_outputs.is_empty()
        || wanted.iter().any(|wanted| {
            agent_outputs
                .iter()
                .any(|offered| media_type(wanted).eq_ignore_ascii_case(media_type(offered)))
        })
    {
        Ok(())
    } else {
        Err(Unfit::ModesIncompatible)
    }
}

/// MIME type and subtype are case-insensitive; parameters do not change the structural mode.
fn media_type(mode: &str) -> &str {
    mode.split(';').next().unwrap_or_default().trim()
}

#[cfg(test)]
#[path = "tests/skill_tests.rs"]
mod tests;
