// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use std::cell::Cell;

struct Signing {
    kid: String,
    signs: usize,
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
