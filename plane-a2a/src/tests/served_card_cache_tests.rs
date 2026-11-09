// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use std::cell::Cell;

struct Signing {
    kid: String,
    signs: usize,
}

struct Unsigned;
impl Signer for Unsigned {
    fn kid(&mut self) -> Option<String> {
        None
    }
    fn sign(&mut self, _: &[u8]) -> Option<Vec<u8>> {
        None
    }
}

#[test]
fn own_card_validators_follow_representation_and_generation() {
    let cache = CardCache::default();
    let serve = |generation, cached, card: Value| {
        cache
            .serve(generation, cached, None, None, &mut Unsigned, || Ok(card))
            .unwrap()
    };
    let body = serve(1, true, serde_json::json!({}));
    let initial = cache.validators(1, &body, Some(0));
    assert_eq!(
        initial.0,
        "\"44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a\""
    );
    assert_eq!(initial.1.as_deref(), Some("Thu, 01 Jan 1970 00:00:00 GMT"));
    assert_eq!(cache.validators(1, &body, Some(60)), initial);
    let retry = serve(1, false, serde_json::json!({}));
    assert_eq!(
        cache.validators(1, &retry, Some(120)),
        initial,
        "short-write re-entry keeps validators"
    );
    let changed = serve(1, true, serde_json::json!({"name":"changed"}));
    // A cached own card is reused until its generation changes.
    assert_eq!(changed, body);
    let changed = serve(2, true, serde_json::json!({"name":"changed"}));
    let updated = cache.validators(2, &changed, Some(86_400));
    assert_ne!(updated.0, initial.0);
    assert_eq!(updated.1.as_deref(), Some("Fri, 02 Jan 1970 00:00:00 GMT"));
    let third = serve(3, true, serde_json::json!({}));
    assert_eq!(
        cache.validators(3, &third, None).1,
        None,
        "no fabricated clock reading"
    );
    assert_eq!(
        cache.validators(3, &third, Some(951_782_400)).1.as_deref(),
        Some("Tue, 29 Feb 2000 00:00:00 GMT")
    );
}
impl Signer for Signing {
    fn kid(&mut self) -> Option<String> {
        Some(self.kid.clone())
    }
    fn sign(&mut self, _: &[u8]) -> Option<Vec<u8>> {
        self.signs += 1;
        Some(vec![7; 64])
    }
}

#[test]
fn cards_reuse_signatures_until_document_generation_or_key_changes() {
    let cache = CardCache::default();
    let source = Arc::new(serde_json::json!({"name":"agent"}));
    let built = Cell::new(0);
    let mut signer = Signing {
        kid: "first".into(),
        signs: 0,
    };
    let serve = |generation, source: &Arc<Value>, signer: &mut Signing, allowed| {
        cache
            .serve(
                generation,
                allowed,
                Some("agent"),
                Some(source),
                signer,
                || {
                    built.set(built.get() + 1);
                    Ok((**source).clone())
                },
            )
            .unwrap()
    };
    let first = serve(1, &source, &mut signer, true);
    assert_eq!(first, serve(1, &source, &mut signer, true));
    assert_eq!((built.get(), signer.signs), (1, 1));
    // Output SHORT re-entry repeats the original service sequence even if another unit cached it.
    assert_eq!(first, serve(1, &source, &mut signer, false));
    assert_eq!((built.get(), signer.signs), (2, 2));
    signer.kid = "second".into();
    assert_ne!(first, serve(1, &source, &mut signer, true));
    let replacement = Arc::new(serde_json::json!({"name":"changed"}));
    let _ = serve(1, &replacement, &mut signer, true);
    let _ = serve(2, &replacement, &mut signer, true);
    assert_eq!((built.get(), signer.signs), (5, 5));
    cache.retire(2);
    let _ = serve(2, &replacement, &mut signer, true);
    assert_eq!((built.get(), signer.signs), (6, 6));
}

#[test]
fn cache_caps_entries_and_does_not_reuse_other_agents_documents() {
    let cache = CardCache::default();
    let mut signer = Signing {
        kid: "key".into(),
        signs: 0,
    };
    for i in 0..MAX_ENTRIES + 1 {
        cache
            .serve(1, true, Some(&i.to_string()), None, &mut signer, || {
                Ok(serde_json::json!({"name":i}))
            })
            .unwrap();
    }
    assert_eq!(cache.entries.with_all(|entries| entries.len()), MAX_ENTRIES);
    assert!(
        cache
            .entries
            .with_all(|entries| entries.values().map(|e| e.body.len()).sum::<usize>())
            <= MAX_BYTES
    );
}
