// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE gRPC LINE'S MESSAGES and the SDK's conversion rules over them.

use crate::wkt::{value::Kind, Struct, Timestamp, Value};

#[path = "proto_custody.rs"]
pub(crate) mod custody;

/// The `lf.a2a.v1` package.
#[allow(
    missing_docs,
    clippy::all,
    clippy::pedantic,
    unknown_lints,
    clippy::useless_borrows_in_formatting
)]
pub mod pb {
    include!(concat!(env!("OUT_DIR"), "/lf.a2a.v1.rs"));
    include!(concat!(env!("OUT_DIR"), "/lf.a2a.v1.serde.rs"));
}

/// The full service name the generated descriptor names (`package.Service`).
#[cfg(test)]
pub const SERVICE_NAME: &str = "lf.a2a.v1.A2AService";

/// The interface binding whose URL the model writes without an `http://` scheme.
use crate::binding::BINDING_GRPC as GRPC_BINDING;

/// A message missing required data (the SDK's `MissingPayload`, named by the model type it was for).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MissingPayload(pub &'static str);

impl std::fmt::Display for MissingPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ProtoJSON payload missing required data for {}", self.0)
    }
}

/// THE MODEL'S ROUND TRIP over one message, in place.
pub trait Normal {
    /// Apply it.
    fn normal(&mut self) -> Result<(), MissingPayload>;
}

fn value(v: &mut Value) {
    match &mut v.kind {
        None | Some(Kind::Null(_)) => v.kind = Some(Kind::Null(0)),
        Some(Kind::Number(n)) if !n.is_finite() => v.kind = Some(Kind::Null(0)),
        Some(Kind::List(list)) => list.values.iter_mut().for_each(value),
        Some(Kind::Struct(s)) => strukt(s),
        Some(Kind::Number(_) | Kind::String(_) | Kind::Bool(_)) => {}
    }
}

fn strukt(s: &mut Struct) {
    s.fields.values_mut().for_each(value);
}

fn metadata(s: &mut Option<Struct>) {
    if let Some(s) = s.as_mut() {
        strukt(s);
    }
}

/// A timestamp the model cannot represent is dropped.
fn timestamp(ts: &mut Option<Timestamp>) {
    let representable = ts
        .as_ref()
        .is_none_or(|t| crate::wkt::representable(t.seconds, t.nanos));
    if !representable {
        *ts = None;
    }
}

fn role(r: &mut i32) {
    if !matches!(pb::Role::try_from(*r), Ok(pb::Role::User | pb::Role::Agent)) {
        *r = pb::Role::Unspecified as i32;
    }
}

fn task_state(s: &mut i32) {
    if pb::TaskState::try_from(*s).is_err() {
        *s = pb::TaskState::Unspecified as i32;
    }
}

impl Normal for pb::Part {
    fn normal(&mut self) -> Result<(), MissingPayload> {
        match &mut self.content {
            None => self.content = Some(pb::part::Content::Text(String::new())),
            Some(pb::part::Content::Data(d)) => value(d),
            Some(_) => {}
        }
        metadata(&mut self.metadata);
        Ok(())
    }
}

impl Normal for pb::Message {
    fn normal(&mut self) -> Result<(), MissingPayload> {
        role(&mut self.role);
        for p in &mut self.parts {
            p.normal()?;
        }
        metadata(&mut self.metadata);
        Ok(())
    }
}

impl Normal for pb::TaskStatus {
    fn normal(&mut self) -> Result<(), MissingPayload> {
        task_state(&mut self.state);
        if let Some(m) = self.message.as_mut() {
            m.normal()?;
        }
        timestamp(&mut self.timestamp);
        Ok(())
    }
}

impl Normal for pb::Artifact {
    fn normal(&mut self) -> Result<(), MissingPayload> {
        for p in &mut self.parts {
            p.normal()?;
        }
        metadata(&mut self.metadata);
        Ok(())
    }
}

fn status(s: &mut Option<pb::TaskStatus>) -> Result<(), MissingPayload> {
    s.get_or_insert_with(pb::TaskStatus::default).normal()
}

impl Normal for pb::Task {
    fn normal(&mut self) -> Result<(), MissingPayload> {
        status(&mut self.status)?;
        for a in &mut self.artifacts {
            a.normal()?;
        }
        for m in &mut self.history {
            m.normal()?;
        }
        metadata(&mut self.metadata);
        Ok(())
    }
}

/// The messages the model carries field for field.
macro_rules! identity {
    ($($t:ty),* $(,)?) => {
        $(impl Normal for $t {
            fn normal(&mut self) -> Result<(), MissingPayload> {
                Ok(())
            }
        })*
    };
}

identity!(
    pb::TaskPushNotificationConfig,
    pb::GetTaskRequest,
    pb::SubscribeToTaskRequest,
    pb::GetExtendedAgentCardRequest,
    pb::GetTaskPushNotificationConfigRequest,
    pb::DeleteTaskPushNotificationConfigRequest,
    pb::ListTaskPushNotificationConfigsRequest,
    pb::ListTaskPushNotificationConfigsResponse,
);

impl Normal for pb::SendMessageRequest {
    fn normal(&mut self) -> Result<(), MissingPayload> {
        self.message
            .as_mut()
            .ok_or(MissingPayload("SendMessageRequest.message"))?
            .normal()?;
        metadata(&mut self.metadata);
        Ok(())
    }
}

impl Normal for pb::ListTasksRequest {
    fn normal(&mut self) -> Result<(), MissingPayload> {
        task_state(&mut self.status);
        self.page_size = self.page_size.filter(|n| *n > 0);
        timestamp(&mut self.status_timestamp_after);
        Ok(())
    }
}

impl Normal for pb::ListTasksResponse {
    fn normal(&mut self) -> Result<(), MissingPayload> {
        for t in &mut self.tasks {
            t.normal()?;
        }
        Ok(())
    }
}

impl Normal for pb::CancelTaskRequest {
    fn normal(&mut self) -> Result<(), MissingPayload> {
        metadata(&mut self.metadata);
        Ok(())
    }
}

impl Normal for pb::SendMessageResponse {
    fn normal(&mut self) -> Result<(), MissingPayload> {
        use pb::send_message_response::Payload;
        match &mut self.payload {
            Some(Payload::Task(t)) => t.normal(),
            Some(Payload::Message(m)) => m.normal(),
            None => Err(MissingPayload("SendMessageResponse")),
        }
    }
}

impl Normal for pb::TaskStatusUpdateEvent {
    fn normal(&mut self) -> Result<(), MissingPayload> {
        status(&mut self.status)?;
        metadata(&mut self.metadata);
        Ok(())
    }
}

impl Normal for pb::TaskArtifactUpdateEvent {
    fn normal(&mut self) -> Result<(), MissingPayload> {
        self.artifact
            .get_or_insert_with(pb::Artifact::default)
            .normal()?;
        metadata(&mut self.metadata);
        Ok(())
    }
}

impl Normal for pb::StreamResponse {
    fn normal(&mut self) -> Result<(), MissingPayload> {
        use pb::stream_response::Payload;
        match &mut self.payload {
            Some(Payload::Task(t)) => t.normal(),
            Some(Payload::Message(m)) => m.normal(),
            Some(Payload::StatusUpdate(s)) => s.normal(),
            Some(Payload::ArtifactUpdate(a)) => a.normal(),
            None => Err(MissingPayload("StreamResponse")),
        }
    }
}

impl Normal for pb::AgentInterface {
    fn normal(&mut self) -> Result<(), MissingPayload> {
        if self.protocol_binding.eq_ignore_ascii_case(GRPC_BINDING) {
            if let Some(stripped) = self.url.strip_prefix("http://") {
                let replacement = stripped.to_string();
                custody::Wipe::wipe(&mut self.url);
                self.url = replacement;
            }
        }
        Ok(())
    }
}

impl Normal for pb::AgentCapabilities {
    fn normal(&mut self) -> Result<(), MissingPayload> {
        for e in &mut self.extensions {
            metadata(&mut e.params);
        }
        Ok(())
    }
}

impl Normal for pb::SecurityScheme {
    fn normal(&mut self) -> Result<(), MissingPayload> {
        if let Some(pb::security_scheme::Scheme::Oauth2SecurityScheme(oa)) = &mut self.scheme {
            let flowless = oa.flows.as_ref().is_none_or(|f| f.flow.is_none());
            if flowless {
                oa.flows = Some(pb::OAuthFlows {
                    flow: Some(pb::o_auth_flows::Flow::ClientCredentials(
                        pb::ClientCredentialsOAuthFlow::default(),
                    )),
                });
            }
        }
        Ok(())
    }
}

impl Normal for pb::AgentCard {
    fn normal(&mut self) -> Result<(), MissingPayload> {
        for i in &mut self.supported_interfaces {
            i.normal()?;
        }
        self.capabilities
            .get_or_insert_with(pb::AgentCapabilities::default)
            .normal()?;

        let removed: Vec<_> = self
            .security_schemes
            .iter()
            .filter(|(_, scheme)| scheme.scheme.is_none())
            .map(|(key, _)| custody::Guard::new(key.clone()))
            .collect();
        for key in removed {
            if let Some((mut key, mut scheme)) = self.security_schemes.remove_entry(&*key) {
                custody::Wipe::wipe(&mut key);
                custody::Wipe::wipe(&mut scheme);
            }
        }
        for s in self.security_schemes.values_mut() {
            s.normal()?;
        }
        for s in &mut self.signatures {
            metadata(&mut s.header);
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "tests/proto_tests.rs"]
mod tests;
