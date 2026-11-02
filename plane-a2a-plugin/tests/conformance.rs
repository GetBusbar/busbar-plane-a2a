// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Ordinary admission and privacy assertions over actual linked and dropped A2A images.

// Relay and lifecycle assertions run through the actual root and Store. Generic connection,
// layout, and failed-READY assertions are retained at their ordinary owning boundaries.
mod actual_admission {
    use busbar_contract::abi::mechanism::KindCode;
    use busbar_plugin_loader::dispatch::kinds::plane::Plane;
    use busbar_plugin_loader::dispatch::{
        load_dropped, load_linked, rendering_of_library, Bind, ConnTable, DispatchConfig,
        Dispatcher, LinkedRow, LoadError, NoSink,
    };
    use std::path::PathBuf;
    use std::sync::Arc;

    fn image() -> PathBuf {
        let path = if let Some(path) = std::env::var_os("BUSBAR_PLUGIN_CDYLIB") {
            let path = PathBuf::from(path);
            assert!(path.is_absolute(), "BUSBAR_PLUGIN_CDYLIB must be absolute");
            path
        } else {
            let exe = std::env::current_exe().expect("test executable");
            exe.parent().expect("test deps directory").join(
                busbar_plugin_loader::plugin_library_filename("busbar_plane_a2a_plugin"),
            )
        };
        assert!(
            path.is_file(),
            "fresh actual A2A cdylib missing: {}; build this product first",
            path.display()
        );
        path
    }
    fn bind(d: &Dispatcher) -> Bind {
        Bind {
            instance: Arc::from("actual-a2a-admission"),
            max_inflight_cap: 64,
            sink: Arc::new(NoSink),
            dispatcher: d.adopter(),
            conns: ConnTable::Probe,
        }
    }

    #[test]
    fn actual_linked_and_fresh_dropped_a2a_have_the_same_statement() {
        let row = LinkedRow::of_macro(busbar_plane_a2a::MACRO_DOOR).unwrap();
        let stated = rendering_of_library(&image())
            .expect("actual image renders")
            .expect("actual image exports its door");
        assert_eq!(stated, row.statement);
        let d = Dispatcher::new(DispatchConfig::default());
        let linked = load_linked::<Plane>(&row, bind(&d)).expect("actual linked plane loads");
        let dropped =
            load_dropped::<Plane>(&image(), &stated, bind(&d)).expect("actual dropped plane loads");
        assert_eq!(linked.name(), dropped.name());
        assert_eq!(linked.kind(), KindCode::Plane);
        assert_eq!(dropped.kind(), KindCode::Plane);
        let (door_address, ops_address) =
            busbar_plugin_loader::dispatch::load::door_addresses_of_library(&image())
                .expect("actual dropped image opens")
                .expect("actual dropped image has a door");
        let linked_address = busbar_plane_a2a::door();
        // SAFETY: actual published plane door points to a complete static SDK table.
        let linked_parts =
            unsafe { busbar_contract::abi::mechanism::door::Door::read_parts(linked_address) };
        assert_ne!(
            door_address, linked_address as *const _ as usize,
            "the actual images have distinct doors"
        );
        assert_ne!(
            ops_address, linked_parts.ops as usize,
            "the actual images have distinct operation tables"
        );
        for product in [&linked, &dropped] {
            use busbar_contract::abi::mechanism::call::{AbiStr, Blob, Outcome, BLOB_JSON};
            use busbar_contract::abi::plane::{PlaneOpenIn, PlaneOpenOut};
            use busbar_plugin_loader::dispatch::{in_head, out_head, Frame};
            use std::sync::atomic::Ordering;
            let settings = serde_json::to_vec(
                &serde_json::from_str::<serde_json::Value>(include_str!("conformance.json"))
                    .unwrap()["settings"],
            )
            .unwrap();
            // SAFETY: plane frames are plain C integer/pointer fields with valid zero defaults.
            let mut frame: Frame<PlaneOpenIn, PlaneOpenOut> =
                Frame::new(unsafe { std::mem::zeroed() }, unsafe { std::mem::zeroed() });
            frame.input.open.head = in_head();
            frame.out.open.head = out_head();
            frame.input.open.generation = 1;
            // SAFETY: settings and static public URL live throughout OPEN.
            frame.input.open.settings =
                unsafe { Blob::from_raw_parts(settings.as_ptr(), settings.len(), BLOB_JSON, 0) };
            frame.input.public_url = AbiStr::of("https://gw.example");
            let count = || {
                let resumed = product.inner.resumes.load(Ordering::SeqCst);
                product.inner.crossings.load(Ordering::SeqCst) - resumed
            };
            let before = count();
            let (answer, snapshot) = product.open(&mut frame);
            assert_eq!(
                answer.outcome,
                Outcome::Ready,
                "actual product opens: {answer:?}"
            );
            assert_eq!(count() - before, 1, "one actual OPEN first crossing");
            let snapshot = snapshot.expect("actual OPEN publishes route claims");
            assert_eq!(snapshot.claims.len(), 19, "exact configured open claims");
            let before = count();
            product
                .ready(&d, std::time::Duration::from_secs(30))
                .expect("actual product READY completes");
            assert_eq!(
                count() - before,
                u64::from(product.has_ready()),
                "exact actual READY first crossings"
            );
        }
    }

    #[test]
    fn a_mismatched_statement_is_refused_for_both_actual_a2a_doors() {
        let row = LinkedRow::of_macro(busbar_plane_a2a::MACRO_DOOR).unwrap();
        let mut stated = row.statement.clone();
        let read = busbar_contract::abi::mechanism::rendering::read(&stated).unwrap();
        let name = read.name.as_bytes();
        let at = stated
            .windows(name.len())
            .position(|bytes| bytes == name)
            .unwrap();
        stated[at] = if stated[at] == b'a' { b'b' } else { b'a' };
        assert_ne!(
            busbar_contract::abi::mechanism::rendering::read(&stated)
                .unwrap()
                .name,
            read.name
        );
        let d = Dispatcher::new(DispatchConfig::default());
        let dishonest = LinkedRow {
            statement: stated.clone(),
            ..row
        };
        assert_eq!(
            load_linked::<Plane>(&dishonest, bind(&d)).err(),
            Some(LoadError::StatementMismatch)
        );
        assert_eq!(
            load_dropped::<Plane>(&image(), &stated, bind(&d)).err(),
            Some(LoadError::StatementMismatch)
        );
    }

    #[test]
    fn both_actual_a2a_doors_refuse_every_other_kind() {
        use busbar_plugin_loader::dispatch::kinds;
        let row = LinkedRow::of_macro(busbar_plane_a2a::MACRO_DOOR).unwrap();
        let path = image();
        let d = Dispatcher::new(DispatchConfig::default());
        assert_eq!(
            load_linked::<kinds::auth::Auth>(&row, bind(&d)).err(),
            Some(LoadError::ManifestKind {
                stated: KindCode::Plane,
                want: KindCode::Auth
            })
        );
        assert_eq!(
            load_dropped::<kinds::auth::Auth>(&path, &row.statement, bind(&d)).err(),
            Some(LoadError::ManifestKind {
                stated: KindCode::Plane,
                want: KindCode::Auth
            })
        );
        assert_eq!(
            load_linked::<kinds::export::Export>(&row, bind(&d)).err(),
            Some(LoadError::ManifestKind {
                stated: KindCode::Plane,
                want: KindCode::Export
            })
        );
        assert_eq!(
            load_dropped::<kinds::export::Export>(&path, &row.statement, bind(&d)).err(),
            Some(LoadError::ManifestKind {
                stated: KindCode::Plane,
                want: KindCode::Export
            })
        );
        assert_eq!(
            load_linked::<kinds::hook::Hook>(&row, bind(&d)).err(),
            Some(LoadError::ManifestKind {
                stated: KindCode::Plane,
                want: KindCode::Hook
            })
        );
        assert_eq!(
            load_dropped::<kinds::hook::Hook>(&path, &row.statement, bind(&d)).err(),
            Some(LoadError::ManifestKind {
                stated: KindCode::Plane,
                want: KindCode::Hook
            })
        );
        assert_eq!(
            load_linked::<kinds::secret::Secret>(&row, bind(&d)).err(),
            Some(LoadError::ManifestKind {
                stated: KindCode::Plane,
                want: KindCode::Secret
            })
        );
        assert_eq!(
            load_dropped::<kinds::secret::Secret>(&path, &row.statement, bind(&d)).err(),
            Some(LoadError::ManifestKind {
                stated: KindCode::Plane,
                want: KindCode::Secret
            })
        );
        assert_eq!(
            load_linked::<kinds::store::Store>(&row, bind(&d)).err(),
            Some(LoadError::ManifestKind {
                stated: KindCode::Plane,
                want: KindCode::Store
            })
        );
        assert_eq!(
            load_dropped::<kinds::store::Store>(&path, &row.statement, bind(&d)).err(),
            Some(LoadError::ManifestKind {
                stated: KindCode::Plane,
                want: KindCode::Store
            })
        );
        assert_eq!(
            load_linked::<kinds::transport::Transport>(&row, bind(&d)).err(),
            Some(LoadError::ManifestKind {
                stated: KindCode::Plane,
                want: KindCode::Transport
            })
        );
        assert_eq!(
            load_dropped::<kinds::transport::Transport>(&path, &row.statement, bind(&d)).err(),
            Some(LoadError::ManifestKind {
                stated: KindCode::Plane,
                want: KindCode::Transport
            })
        );
    }

    #[test]
    fn actual_a2a_declares_its_statement_needs_and_requested_release_profile() {
        let row = LinkedRow::of_macro(busbar_plane_a2a::MACRO_DOOR).unwrap();
        let stated = busbar_contract::abi::mechanism::rendering::read(&row.statement).unwrap();
        let declared: serde_json::Value =
            serde_json::from_str(include_str!("../../plane-a2a/declares.json")).unwrap();
        let mut needs: Vec<_> = stated
            .needs
            .iter()
            .map(|need| need.transport.as_str())
            .collect();
        needs.sort();
        needs.dedup();
        let mut declarations: Vec<_> = declared["needs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|need| need.as_str().unwrap())
            .collect();
        declarations.sort();
        declarations.dedup();
        assert_eq!(needs, declarations);
        #[cfg(debug_assertions)]
        assert!(
            std::env::var_os("BUSBAR_EXPECT_RELEASE").is_none(),
            "the requested actual image proof must run in release"
        );
    }
    /// These inputs change admission metadata only; all operation slots remain actual A2A.
    #[test]
    fn actual_a2a_rejects_incompatible_kind_abi_layout_and_plane_answer_layout() {
        use busbar_contract::abi::mechanism::door::{Door, DoorParts, KindTailHead, Statement};
        use busbar_contract::abi::plane::{PlaneTail, ANSWER_LAYOUT};
        use busbar_plugin_loader::dispatch::load::rendering_of_raw;
        use std::sync::atomic::{AtomicPtr, Ordering};
        static MUTATED: AtomicPtr<Door> = AtomicPtr::new(std::ptr::null_mut());
        extern "C" fn malformed() -> *const Door {
            MUTATED.load(Ordering::SeqCst)
        }
        let row = LinkedRow::of_macro(busbar_plane_a2a::MACRO_DOOR).unwrap();
        let path = image();
        let d = Dispatcher::new(DispatchConfig::default());
        // SAFETY: the real published SDK door and its full operation table are static.
        let real = unsafe { Door::read_parts(busbar_plane_a2a::door()) };
        assert_eq!(real.kind_abi, KindCode::Plane.abi_version());
        assert_eq!(real.layout, KindCode::Plane.layout_fingerprint());
        for abi in [real.kind_abi + 1, real.kind_abi.wrapping_sub(1)] {
            // SAFETY: retain static actual product pointers, changing only admission metadata.
            let bad = unsafe {
                Door::__from_parts(DoorParts {
                    kind_abi: abi,
                    ..real
                })
            };
            MUTATED.store(Box::into_raw(Box::new(bad)), Ordering::SeqCst);
            let expected = LoadError::KindAbi {
                kind: KindCode::Plane,
                door: abi,
                host: real.kind_abi,
            };
            assert_eq!(rendering_of_raw(malformed).err(), Some(expected.clone()));
            assert_eq!(LinkedRow::of_raw(malformed).err(), Some(expected.clone()));
            let stated = LinkedRow {
                statement: row.statement.clone(),
                door: malformed,
            };
            assert_eq!(
                load_linked::<Plane>(&stated, bind(&d)).err(),
                Some(expected)
            );
            let mut manifest = row.statement.clone();
            let at = busbar_contract::abi::mechanism::rendering::RENDERING_MAGIC.len() + 8;
            manifest[at..at + 4].copy_from_slice(&abi.to_le_bytes());
            assert_eq!(
                load_dropped::<Plane>(&path, &manifest, bind(&d)).err(),
                Some(LoadError::ManifestKindAbi {
                    stated: abi,
                    host: real.kind_abi
                })
            );
        }
        for layout in [real.layout ^ 1, 0] {
            // SAFETY: all immutable actual product pointers are retained.
            let bad = unsafe { Door::__from_parts(DoorParts { layout, ..real }) };
            MUTATED.store(Box::into_raw(Box::new(bad)), Ordering::SeqCst);
            let refused = rendering_of_raw(malformed).unwrap_err();
            match &refused {
                LoadError::KindLayout {
                    kind, stated, host, ..
                } => assert_eq!(
                    (*kind, *stated, *host),
                    (KindCode::Plane, layout, real.layout)
                ),
                other => panic!("expected exact kind layout refusal: {other:?}"),
            }
            assert!(refused
                .to_string()
                .contains("rebuild against this busbar-contract"));
            assert_eq!(LinkedRow::of_raw(malformed).err(), Some(refused.clone()));
            let stated = LinkedRow {
                statement: row.statement.clone(),
                door: malformed,
            };
            assert_eq!(load_linked::<Plane>(&stated, bind(&d)).err(), Some(refused));
        }
        // SAFETY: actual admitted Statement and tail are immutable static plane data.
        let statement = unsafe { real.statement.read_unaligned() };
        let tail_size = unsafe { statement.kind_tail.read_unaligned() }.size as usize;
        // SAFETY: PlaneTail is plain ABI integer/pointer data with valid zero defaults.
        let mut tail: PlaneTail = unsafe { std::mem::zeroed() };
        // SAFETY: copy only the bytes present in the source tail and fitting the target.
        unsafe {
            std::ptr::copy_nonoverlapping(
                statement.kind_tail.cast::<u8>(),
                std::ptr::from_mut(&mut tail).cast::<u8>(),
                tail_size.min(std::mem::size_of::<PlaneTail>()),
            )
        };
        tail.answer_layout = ANSWER_LAYOUT - 1;
        let tail = Box::leak(Box::new(tail));
        let statement = Box::leak(Box::new(Statement {
            kind_tail: std::ptr::from_ref(tail).cast::<KindTailHead>(),
            ..statement
        }));
        // SAFETY: only plane answer-layout metadata changes, keeping real static product slots.
        let bad = unsafe { Door::__from_parts(DoorParts { statement, ..real }) };
        MUTATED.store(Box::into_raw(Box::new(bad)), Ordering::SeqCst);
        let refused = rendering_of_raw(malformed).unwrap_err();
        match &refused {
            LoadError::PlaneLayout { stated, host, .. } => {
                assert_eq!((*stated, *host), (ANSWER_LAYOUT - 1, ANSWER_LAYOUT))
            }
            other => panic!("expected exact plane layout refusal: {other:?}"),
        }
        assert!(refused
            .to_string()
            .contains("rebuild against this busbar-contract"));
        assert_eq!(LinkedRow::of_raw(malformed).err(), Some(refused));
    }
    /// The only configured canary is in a rejected URL. No opened Store or host facade is needed.
    #[test]
    fn rejected_userinfo_never_crosses_back_from_validate_or_open_in_either_image() {
        use busbar_contract::abi::mechanism::call::{Blob, Outcome, BLOB_JSON};
        use busbar_contract::abi::mechanism::lifecycle::{slot, ValidateIn};
        use busbar_contract::abi::plane::{PlaneOpenIn, PlaneOpenOut};
        use busbar_plugin_loader::dispatch::{
            in_head, out_head, Diagnostic, Dropped, EnvelopeSink, Frame, Metric,
        };
        use std::sync::atomic::{AtomicBool, Ordering};
        #[derive(Default)]
        struct A2aRefusalEnvelopes {
            bytes: std::sync::Mutex<Vec<Vec<u8>>>,
            dropped: AtomicBool,
        }
        impl EnvelopeSink for A2aRefusalEnvelopes {
            fn metric(&self, metric: Metric<'_>) {
                self.bytes
                    .lock()
                    .unwrap()
                    .extend(metric.labels.iter().map(|label| label.to_vec()));
            }
            fn diag(&self, diagnostic: Diagnostic<'_>) {
                self.bytes
                    .lock()
                    .unwrap()
                    .extend([diagnostic.name.to_vec(), diagnostic.text.to_vec()]);
            }
            fn dropped(&self, _: Dropped) {
                self.dropped.store(true, Ordering::SeqCst);
            }
        }
        let inputs: serde_json::Value =
            serde_json::from_str(include_str!("conformance.json")).unwrap();
        let credentials = inputs["credentials"].as_array().unwrap();
        assert_eq!(
            credentials.len(),
            1,
            "this product property names the actual configured canary"
        );
        let secret = credentials[0].as_str().unwrap().as_bytes();
        assert!(!secret.is_empty());
        let bad = &inputs["plane"]["bad_settings"][0];
        assert!(
            bad["vendor"]["url"]
                .as_str()
                .unwrap()
                .as_bytes()
                .windows(secret.len())
                .any(|part| part == secret),
            "the invalid URL actually carries the configured canary"
        );
        // Preserve the pinned canary algorithm's raw, percent (both cases), base64 (both
        // alphabets, unpadded) and hex (both cases) spellings without a new dependency/framework.
        let percent = |upper: bool| -> Vec<u8> {
            secret
                .iter()
                .flat_map(|byte| {
                    if byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'.' | b'_' | b'~') {
                        vec![*byte]
                    } else if upper {
                        format!("%{byte:02X}").into_bytes()
                    } else {
                        format!("%{byte:02x}").into_bytes()
                    }
                })
                .collect()
        };
        let base64 = |alphabet: &[u8]| -> Vec<u8> {
            let mut encoded = Vec::new();
            for block in secret.chunks(3) {
                let a = block[0];
                let b = block.get(1).copied().unwrap_or(0);
                let c = block.get(2).copied().unwrap_or(0);
                encoded.push(alphabet[usize::from(a >> 2)]);
                encoded.push(alphabet[usize::from(((a & 3) << 4) | (b >> 4))]);
                if block.len() > 1 {
                    encoded.push(alphabet[usize::from(((b & 15) << 2) | (c >> 6))]);
                }
                if block.len() > 2 {
                    encoded.push(alphabet[usize::from(c & 63)]);
                }
            }
            encoded
        };
        let mut spellings = vec![
            secret.to_vec(),
            percent(true),
            percent(false),
            base64(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"),
            base64(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"),
            secret
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
                .into_bytes(),
            secret
                .iter()
                .map(|byte| format!("{byte:02X}"))
                .collect::<String>()
                .into_bytes(),
        ];
        spellings.sort();
        spellings.dedup();
        let settings = serde_json::to_vec(bad).unwrap();
        let expected = b"`agents.vendor`: `url:` carries a userinfo (`user@` or `user:password@`) in its authority; name the agent's credential under `upstream_credential:`, never in its URL";
        let row = LinkedRow::of_macro(busbar_plane_a2a::MACRO_DOOR).unwrap();
        let path = image();
        for dropped in [false, true] {
            let sink = Arc::new(A2aRefusalEnvelopes::default());
            let d = Dispatcher::new(DispatchConfig::default());
            let bound = Bind {
                sink: sink.clone(),
                ..bind(&d)
            };
            let product = if dropped {
                load_dropped::<Plane>(&path, &row.statement, bound)
            } else {
                load_linked::<Plane>(&row, bound)
            }
            .unwrap();
            let first = || {
                let resumes = product.inner.resumes.load(Ordering::SeqCst);
                product.inner.crossings.load(Ordering::SeqCst) - resumes
            };
            let mut emitted = Vec::new();
            let mut reason = vec![0_u8; expected.len() + 64];
            // SAFETY: settings and exclusive complete reason buffer remain live for VALIDATE.
            let blob =
                unsafe { Blob::from_raw_parts(settings.as_ptr(), settings.len(), BLOB_JSON, 0) };
            let mut validate = Frame::new(
                ValidateIn {
                    head: in_head(),
                    settings: blob,
                    err_buf: reason.as_mut_ptr(),
                    err_cap: reason.len(),
                },
                out_head(),
            );
            let before = first();
            let answer = product.call(slot::VALIDATE, &mut validate);
            assert_eq!(answer.outcome, Outcome::Refused);
            assert_eq!(answer.error.as_deref(), Some(expected.as_slice()));
            assert_eq!(answer.lease, 0, "rejected validation owes no lease release");
            assert_eq!(first() - before, 1, "one real validation first crossing");
            emitted.push(answer.error.unwrap());
            emitted.push(reason.clone());
            reason.fill(0);
            // SAFETY: plane OPEN frames are plain C ABI data with valid zero defaults.
            let mut open: Frame<PlaneOpenIn, PlaneOpenOut> =
                Frame::new(unsafe { std::mem::zeroed() }, unsafe { std::mem::zeroed() });
            open.input.open.head = in_head();
            open.out.open.head = out_head();
            open.input.open.generation = 1;
            open.input.open.settings = blob;
            open.input.open.err_buf = reason.as_mut_ptr();
            open.input.open.err_cap = reason.len();
            let before = first();
            let (answer, snapshot) = product.open(&mut open);
            assert_eq!(answer.outcome, Outcome::Refused);
            assert_eq!(answer.error.as_deref(), Some(expected.as_slice()));
            assert_eq!(answer.lease, 0, "refused OPEN publishes no lease");
            assert!(snapshot.is_none(), "refused OPEN publishes no snapshot");
            assert!(
                open.out.open.instance.is_null(),
                "refused OPEN creates no instance"
            );
            assert_eq!(first() - before, 1, "one real refused OPEN first crossing");
            assert_eq!(
                open.out.open.err_len,
                expected.len(),
                "complete error without truncation"
            );
            emitted.push(answer.error.unwrap());
            emitted.push(reason);
            let before = first();
            let mut close = Frame::new(in_head(), out_head());
            let closed = product.call(slot::CLOSE, &mut close);
            assert_eq!(
                closed.outcome,
                Outcome::Refused,
                "the host refuses CLOSE of a never-opened instance"
            );
            assert_eq!(closed.lease, 0);
            assert_eq!(
                first(),
                before,
                "CLOSE of a never-opened instance makes no product crossing"
            );
            emitted.extend(closed.error);
            drop(product);
            assert!(
                !sink.dropped.load(Ordering::SeqCst),
                "all real diagnostic and metric bytes must be captured"
            );
            emitted.extend(sink.bytes.lock().unwrap().iter().cloned());
            for bytes in emitted {
                assert!(
                    !spellings
                        .iter()
                        .any(|needle| bytes.windows(needle.len()).any(|part| part == needle)),
                    "configured credential crossed back from actual image (dropped={dropped})"
                );
            }
        }
    }
}
