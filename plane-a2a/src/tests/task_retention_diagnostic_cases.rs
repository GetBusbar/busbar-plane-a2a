// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

struct Listing<'a> {
    desk: &'a mut Desk,
    halt: Option<Halt>,
    listed: usize,
}

impl Records for Listing<'_> {
    fn get(&mut self, kind: &str, key: &str) -> Result<Option<Vec<u8>>, Halt> {
        self.desk.get(kind, key)
    }
    fn list(&mut self, kind: &str, prefix: &str) -> Result<Vec<(String, Vec<u8>)>, Halt> {
        assert_eq!(
            (kind, prefix),
            (KIND_TASK, ""),
            "the failure is the retention listing"
        );
        self.listed += 1;
        match &self.halt {
            Some(halt) => Err(halt.clone()),
            None => self.desk.list(kind, prefix),
        }
    }
    fn observe_chain_life(&mut self, kind: &str, scope: &str) -> Result<Option<Vec<u8>>, Halt> {
        self.desk.observe_chain_life(kind, scope)
    }
    fn publish(
        &mut self,
        predicates: &[tasks::Predicate],
        chains: &[tasks::ChainLife],
        writes: &[Write],
    ) -> Result<bool, Halt> {
        self.desk.publish(predicates, chains, writes)
    }
}
impl Reach for Listing<'_> {
    fn judge(&mut self, dest: &str) -> Result<u64, Halt> {
        self.desk.judge(dest)
    }
}
impl Mint for Listing<'_> {
    fn random(&mut self, buf: &mut [u8]) -> Result<(), Halt> {
        self.desk.random(buf)
    }
}

#[test]
fn retention_list_failure_is_reported_without_rejecting_the_submission_or_leaking_store_text() {
    for halt in [
        None,
        Some(Halt::Pending),
        Some(Halt::Failed("store-secret-must-not-be-logged".into())),
    ] {
        let mut desk = desk();
        let mut listing = Listing {
            desk: &mut desk,
            halt: halt.clone(),
            listed: 0,
        };
        let envelope = send(
            json!({"message":{"messageId":"m", "role":"ROLE_USER", "parts":[{"text":"request-secret-must-not-be-logged"}]}}),
        );
        let request = Request {
            envelope: &envelope,
            relayed: None,
            relayed_bytes: None,
            caller: ALICE,
            member: MEMBER,
            addressed: None,
            now: 300,
            sweep: true,
        };
        let (sent, heard) = std::sync::mpsc::channel();
        let result = tracing::subscriber::with_default(Capture(sent), || {
            open(
                &mut listing,
                &request,
                &json!(7),
                &|_| None,
                &mut Vec::new(),
            )
        });
        assert_eq!(
            listing.listed, 1,
            "the submitted task reached the retention listing"
        );
        let lines: Vec<_> = heard.try_iter().collect();
        let banner = crate::diagnostics::A2A_TASK_STATE_UNREAD
            .banner()
            .to_string();
        let diagnostics: Vec<_> = lines
            .iter()
            .filter(|(_, line)| line.contains(&banner))
            .collect();
        match halt {
            Some(Halt::Pending) => {
                assert_eq!(result, Err(Halt::Pending));
                assert!(
                    diagnostics.is_empty(),
                    "pending is not a store failure: {lines:?}"
                );
            }
            Some(Halt::Failed(_)) => {
                assert!(
                    matches!(result, Ok(Opened::Hop { swept: None, .. })),
                    "sweep failure does not reject the submit: {result:?}"
                );
                assert!(
                    !diagnostics.is_empty(),
                    "the actual failed maintenance read is surfaced: {lines:?}"
                );
                assert!(
                    diagnostics
                        .iter()
                        .all(|(level, line)| *level == tracing::Level::WARN
                            && line.contains("retention_sweep")
                            && line.contains(MEMBER)),
                    "the operator sees its stage and agent: {diagnostics:?}"
                );
            }
            None => {
                assert!(matches!(result, Ok(Opened::Hop { swept: Some(0), .. })));
                assert!(
                    diagnostics.is_empty(),
                    "a completed sweep is quiet: {lines:?}"
                );
            }
        }
        assert!(lines.iter().all(|(_, line)| !line.contains("store-secret") && !line.contains("request-secret")), "no raw store/request bytes are journaled: {lines:?}");
    }
}
