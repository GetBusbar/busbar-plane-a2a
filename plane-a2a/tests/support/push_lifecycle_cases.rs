// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! Actual public callback route: capabilities are minted by the real push-config mirror.
use super::*;
use busbar_contract::abi::host::service::{RecordsGetIn, SignIn, CLAIM_WON, FOUND};
use busbar_contract::abi::mechanism::call::Span;
use serde_json::{json, Value};
#[path = "conditional_callback_host.rs"]
mod conditional_host;

#[path = "refusal_output_cases.rs"]
mod refusal_output_cases;

#[derive(Default)]
struct Script {
    conditional: conditional_host::Host,
    sign_failed: bool,
    wall_ns: u64,
    clock_step_ns: u64,
    read_failed: bool,
    publish_failed: bool,
    read_pending: bool,
    signs: usize,
    gets: usize,
    claims: usize,
    config_failed: bool,
    config_gets: usize,
    full_lists: usize,
    random: u8,
    notifications: usize,
    capture_mirror: bool,
    mirror_stream: Option<u64>,
    mirror_captures: usize,
    mirror_auth: Option<zeroize::Zeroizing<String>>,
}
static SCRIPT: Mutex<Option<Script>> = Mutex::new(None);
fn script<T>(f: impl FnOnce(&mut Script) -> T) -> T {
    f(SCRIPT
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .as_mut()
        .unwrap())
}
fn text(s: AbiStr) -> String {
    if s.is_empty() {
        return String::new();
    }
    // SAFETY: every caller passes a live ABI string during its call or envelope lifetime.
    String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(s.ptr(), s.len()) }).into_owned()
}
struct Reset(Vec<(String, String, Vec<u8>)>);
impl Drop for Reset {
    fn drop(&mut self) {
        *store() = std::mem::take(&mut self.0);
        *SCRIPT.lock().unwrap_or_else(PoisonError::into_inner) = None;
    }
}
extern "C" fn fixed_clock(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: SDK lends ClockNowIn and its live reading slot.
    let i = unsafe { input.cast::<ClockNowIn>().read() };
    let wall_ns = script(|s| {
        let now = s.wall_ns.max(1_800_000_000_000_000_000);
        s.wall_ns = now.saturating_add(s.clock_step_ns);
        now
    });
    unsafe {
        (*i.reading).wall_ns = wall_ns;
        (*i.reading).mono_ns = 5_000_000_000;
    }
    answer(out, Outcome::Ready, 0, 0)
}
extern "C" fn get(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: SDK lends RecordsGetIn and its stated output buffers.
    let i = unsafe { input.cast::<RecordsGetIn>().read() };
    let (failed, pending) = script(|s| {
        s.gets += 1;
        if text(i.kind) == "push_config" {
            s.config_gets += 1;
        }
        (
            s.read_failed || (s.config_failed && text(i.kind) == "push_config"),
            s.read_pending,
        )
    });
    if pending {
        return answer(out, Outcome::Pending, 0, 0);
    }
    if failed {
        return answer(out, Outcome::Failed, 0, 0);
    }
    let row = script(|s| s.conditional.get(i.head, &text(i.kind), &text(i.key)));
    let Some(row) = row else {
        return answer(out, Outcome::Ready, 0, 0);
    };
    if row.len() > i.into.cap || i.into.spans_cap < 1 {
        let result = answer(out, Outcome::Failed, 0, 0);
        // SAFETY: the live ServiceOut reports both complete loan requirements; neither payload
        // buffer has been written on this SHORT path.
        unsafe {
            (*out).needed_bytes = row.len() as u64;
            (*out).needed_items = 1;
        }
        return result;
    }
    // SAFETY: both output capacities were checked above; the SDK lends the byte/span regions
    // exclusively for this synchronous records.get callback.
    unsafe {
        std::ptr::copy_nonoverlapping(row.as_ptr(), i.into.buf, row.len());
        i.into.spans.write(ItemSpan {
            key: Span {
                offset: busbar_contract::abi::mechanism::check::SPAN_ABSENT,
                len: 0,
            },
            value: Span {
                offset: 0,
                len: u32::try_from(row.len()).expect("the fixture record fits its span"),
            },
        });
    }
    let result = answer(out, Outcome::Ready, FOUND, row.len() as u64);
    // SAFETY: this is the callback's live output; its one initialized value span was just written.
    unsafe {
        (*out).items = 1;
    }
    result
}
extern "C" fn claimed(_: HostCtx, _: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    let failed = script(|s| {
        s.claims += 1;
        s.publish_failed
    });
    answer(
        out,
        if failed {
            Outcome::Failed
        } else {
            Outcome::Ready
        },
        CLAIM_WON,
        0,
    )
}
extern "C" fn signed(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    let failed = script(|s| {
        s.signs += 1;
        s.sign_failed
    });
    if failed {
        return answer(out, Outcome::Failed, 0, 0);
    }
    // SAFETY: SDK lends SignIn and its writable buffers.
    let i = unsafe { input.cast::<SignIn>().read() };
    let key = b"fixture";
    let signature = [7u8; 64];
    if i.into.cap < key.len() + signature.len() || i.into.spans_cap < 1 {
        return answer(out, Outcome::Failed, 0, 0);
    }
    unsafe {
        std::ptr::copy_nonoverlapping(key.as_ptr(), i.into.buf, key.len());
        std::ptr::copy_nonoverlapping(
            signature.as_ptr(),
            i.into.buf.add(key.len()),
            signature.len(),
        );
        i.into.spans.write(ItemSpan {
            key: Span {
                offset: 0,
                len: key.len() as u32,
            },
            value: Span {
                offset: key.len() as u32,
                len: signature.len() as u32,
            },
        });
    }
    let result = answer(out, Outcome::Ready, 0, (key.len() + signature.len()) as u64);
    unsafe {
        (*out).items = 1;
    }
    result
}
extern "C" fn listed(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the SDK lends RecordsListIn during the call.
    let i = unsafe { input.cast::<RecordsListIn>().read() };
    let _ = ctx;
    let (fresh, rows) = script(|s| {
        let rows = s.conditional.list(
            i.head,
            &text(i.kind),
            &text(i.prefix),
            &text(i.after),
            if i.limit == 0 {
                usize::MAX
            } else {
                i.limit as usize
            },
        );
        if rows.0 && text(i.kind) == "task" && i.prefix.is_empty() {
            s.full_lists += 1;
        }
        rows
    });
    let _ = fresh;
    let needed: usize = rows.iter().map(|(k, v)| k.len() + v.len()).sum();
    if needed > i.into.cap || rows.len() > i.into.spans_cap {
        let result = answer(out, Outcome::Failed, 0, 0);
        unsafe {
            (*out).needed_bytes = needed as u64;
            (*out).needed_items = rows.len() as u64;
        }
        return result;
    }
    let mut at = 0;
    for (n, (key, value)) in rows.iter().enumerate() {
        // SAFETY: the SDK's live buffers fit the checked complete page.
        unsafe {
            std::ptr::copy_nonoverlapping(key.as_ptr(), i.into.buf.add(at), key.len());
            std::ptr::copy_nonoverlapping(
                value.as_ptr(),
                i.into.buf.add(at + key.len()),
                value.len(),
            );
            i.into.spans.add(n).write(ItemSpan {
                key: Span {
                    offset: at as u32,
                    len: key.len() as u32,
                },
                value: Span {
                    offset: (at + key.len()) as u32,
                    len: value.len() as u32,
                },
            });
        }
        at += key.len() + value.len();
    }
    let result = answer(out, Outcome::Ready, 0, at as u64);
    unsafe {
        (*out).items = rows.len() as u64;
    }
    result
}
extern "C" fn random_fill(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the SDK lends RandomFillIn and its declared byte region.
    let i = unsafe {
        input
            .cast::<busbar_contract::abi::host::service::RandomFillIn>()
            .read()
    };
    let value = script(|s| {
        s.random = s.random.wrapping_add(1);
        s.conditional.random(i.head, s.random)
    });
    if i.into.cap < i.len as usize {
        return answer(out, Outcome::Failed, 0, 0);
    }
    unsafe {
        std::ptr::write_bytes(i.into.buf, value, i.len as usize);
    }
    answer(out, Outcome::Ready, 0, i.len)
}
fn apply(records: &[RecordWrite], arena: &[u8]) {
    let at = |s: Span| arena[s.offset as usize..(s.offset + s.len) as usize].to_vec();
    let mut stored = store();
    for w in records {
        let kind = door_facts::HELD_KINDS[w.kind as usize].to_string();
        let key = String::from_utf8(at(w.key)).unwrap();
        let value = at(w.value);
        stored.retain(|(k, id, _)| *k != kind || *id != key);
        if !value.is_empty() {
            stored.push((kind, key, value));
        }
    }
}
// Borrow the real wire document so parsing never creates an unwiped token copy.
#[derive(serde::Deserialize)]
struct MirrorCreate<'a> {
    #[serde(borrow)]
    id: &'a str,
    #[serde(borrow)]
    method: &'a str,
    #[serde(borrow)]
    params: MirrorParams<'a>,
}
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct MirrorParams<'a> {
    #[serde(borrow)]
    task_id: &'a str,
    #[serde(borrow)]
    push_notification_config: MirrorConfig<'a>,
}
#[derive(serde::Deserialize)]
struct MirrorConfig<'a> {
    #[serde(borrow)]
    id: &'a str,
    #[serde(borrow)]
    url: &'a str,
    #[serde(borrow)]
    authentication: MirrorAuth<'a>,
}
#[derive(serde::Deserialize)]
struct MirrorAuth<'a> {
    #[serde(borrow)]
    schemes: [&'a str; 1],
    #[serde(borrow)]
    credentials: &'a str,
}
extern "C" fn notification_request(
    ctx: HostCtx,
    input: *const c_void,
    out: *mut ServiceOut,
) -> RawOutcome {
    // SAFETY: connector lends the request bytes and descriptor throughout this call.
    let i = unsafe { input.cast::<RequestIn>().read() };
    let piece = unsafe { i.piece.read() };
    if piece.kind == busbar_contract::abi::host::conn::connector::REQUEST_HEAD {
        let bytes = unsafe { std::slice::from_raw_parts(i.buf, i.len) };
        let at = |span: busbar_contract::abi::transport::FrameSpan| {
            &bytes[span.offset as usize..(span.offset + span.len) as usize]
        };
        if at(piece.target) == b"/cb" {
            script(|s| s.notifications += 1);
        } else {
            script(|s| {
                if s.capture_mirror {
                    assert!(
                        at(piece.method) == b"POST" && at(piece.target) == b"/agent",
                        "the current mirror must use the negotiated JSON-RPC agent endpoint"
                    );
                    assert!(
                        s.mirror_stream.is_none(),
                        "the setup sends exactly one mirror head"
                    );
                    s.mirror_stream = Some(i.stream);
                }
            });
        }
    } else if piece.kind == busbar_contract::abi::host::conn::connector::REQUEST_BODY
        && script(|s| s.capture_mirror && s.mirror_stream == Some(i.stream))
    {
        // SAFETY: RequestIn lends this complete body until the synchronous write completes.
        let bytes = unsafe { std::slice::from_raw_parts(i.buf, i.len) };
        let mirror: MirrorCreate<'_> = serde_json::from_slice(bytes)
            .unwrap_or_else(|_| panic!("the actual mirror writes a borrowed v0.3 create document"));
        assert!(
            mirror.id == "busbar-originated"
                && mirror.method == "tasks/pushNotificationConfig/set"
                && mirror.params.task_id == "backend-t1",
            "the current mirror names the negotiated method and actual backend identity"
        );
        let config = mirror.params.push_notification_config;
        assert!(
            config.id == "busbar-backend-t1"
                && config.url == "https://gw.example/a2a/push"
                && config.authentication.schemes == ["Bearer"],
            "the current mirror registers busbar's exact callback destination and scheme"
        );
        let mut auth = zeroize::Zeroizing::new(String::with_capacity(
            "Bearer ".len() + config.authentication.credentials.len(),
        ));
        auth.push_str("Bearer ");
        auth.push_str(config.authentication.credentials);
        script(|s| {
            assert!(
                s.mirror_auth.is_none(),
                "a current mirror credential cannot replace another"
            );
            s.mirror_auth = Some(auth);
            s.mirror_captures += 1;
            s.capture_mirror = false;
        });
    }
    super::write_request(ctx, input, out)
}

extern "C" fn notification_judged(
    _: HostCtx,
    input: *const c_void,
    out: *mut ServiceOut,
) -> RawOutcome {
    // SAFETY: the destination service lends its writable address and span regions.
    let i = unsafe {
        input
            .cast::<busbar_contract::abi::host::service::DestJudgeIn>()
            .read()
    };
    let address = b"93.184.216.34";
    if i.into.cap < address.len() || i.into.spans_cap < 1 {
        let result = answer(out, Outcome::Failed, 0, 0);
        unsafe {
            (*out).needed_bytes = address.len() as u64;
            (*out).needed_items = 1;
        }
        return result;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(address.as_ptr(), i.into.buf, address.len());
        i.into.spans.write(ItemSpan {
            key: Span {
                offset: 0,
                len: address.len() as u32,
            },
            value: Span {
                offset: busbar_contract::abi::mechanism::check::SPAN_ABSENT,
                len: 0,
            },
        });
    }
    let result = answer(out, Outcome::Ready, DEST_ALLOWED, address.len() as u64);
    unsafe {
        (*out).items = 1;
    }
    result
}

fn open_scripted() -> (Reset, Door) {
    let reset = Reset(std::mem::take(&mut *store()));
    *SCRIPT.lock().unwrap_or_else(PoisonError::into_inner) = Some(Script::default());
    (reset, open_scripted_instance())
}

fn open_scripted_instance() -> Door {
    let services = Box::leak(Box::new(HostSlots {
        records_list: Some(listed),
        random_fill: Some(random_fill),
        clock_now: Some(fixed_clock),
        records_get: Some(get),
        records_claim: Some(claimed),
        sign: Some(signed),
        dest_judge: Some(notification_judged),
        ..HOST_SLOTS
    }));
    let conns = Box::leak(Box::new(ConnectorSlots {
        write_request: Some(notification_request),
        ..CONN_SLOTS
    }));
    let tables = Box::leak(Box::new(HostTables {
        services,
        conns,
        ..TABLES.0
    }));
    let mut input: PlaneOpenIn = z();
    input.open = OpenIn {
        head: head::<PlaneOpenIn>(life::OPEN, Ticket::NONE),
        host: tables,
        settings: octets(SECTION),
        generation: 1,
        ..z()
    };
    input.public_url = str_of(b"https://gw.example");
    let mut output: PlaneOpenOut = z();
    output.open.head = out_head::<PlaneOpenOut>();
    // SAFETY: exact public OPEN ABI, live buffers and static host slots.
    let result = unsafe {
        lifecycle().open.unwrap()(
            std::ptr::null_mut(),
            std::ptr::from_ref(&input).cast(),
            std::ptr::from_mut(&mut output).cast(),
        )
    };
    assert_eq!(result.outcome(), Outcome::Ready);
    Door::new(output.open.instance)
}
fn seed() {
    // A current ready-store snapshot exercises an actual working transition;
    // the separate guarded backend mapping must not substitute for that state publication.
    seed_task("t1", "input-required");
}
fn seed_task(task_id: &str, state: &str) {
    let caller = std::str::from_utf8(ALICE).unwrap();
    let row = json!({"task_id":task_id,"context_id":"c1","principal":caller,"direction":"inbound","state":state,"agent_id":"vendor","artifact_cursor":0,"push_callback":"","created_at":1_800_000_000u64,"updated_at":1_800_000_000u64,"next_seq":1});
    assert!(matches!(state, "input-required" | "working"));
    let mut rows = store();
    assert!(!rows
        .iter()
        .any(|(kind, key, _)| kind == "task" && key == &format!("{caller}/{task_id}")));
    rows.push((
        "task".into(),
        format!("{caller}/{task_id}"),
        serde_json::to_vec(&row).unwrap(),
    ));
    // These fixtures start with existing current-format active tasks, not an empty store.
    // Hold their matching ready counters so no unsupported populated bootstrap is required.
    let active = rows.iter().filter(|(kind, _, _)| kind == "task").count();
    rows.retain(|(kind, _, _)| kind != "task_quota");
    for key in ["active/v1".to_string(), format!("1/{caller}")] {
        rows.push((
            "task_quota".into(),
            key,
            serde_json::to_vec(&json!({"version":1,"epoch":1,"active":active})).unwrap(),
        ));
    }
}
fn registered(door: &Door) -> zeroize::Zeroizing<String> {
    assert_eq!(door.connect("vendor").1, 200);
    seed();
    let get = br#"{"jsonrpc":"2.0","id":1,"method":"GetTask","params":{"id":"t1"}}"#;
    assert_eq!(
        door.arrive(
            501,
            ("POST", "/a2a/agents/{agent_id}"),
            "/a2a/agents/vendor",
            get
        ),
        (Outcome::Ready, 0)
    );
    let attempt = piece(door, 501, Given::attempt(b"vendor"), 65536);
    assert_eq!(
        attempt.outcome,
        Some(Outcome::Ready),
        "flags={}, emitted_bytes={}",
        attempt.flags,
        attempt.emitted.len()
    );
    assert_ne!(attempt.flags & busbar_contract::abi::plane::EMIT_TO_FAR_END, 0,
        "the setup must actually reach the agent (flags={}, emitted_bytes={}, publications={}, observations={})",
        attempt.flags, attempt.emitted.len(), script(|s| s.conditional.requests.len()), script(|s| s.conditional.observations.len()));
    assert_eq!(
        piece(door, 501, Given::caller(get), 65536).outcome,
        Some(Outcome::Ready)
    );
    let applied = script(|s| s.conditional.applied);
    let publications = script(|s| s.conditional.requests.len());
    let quota_before: Vec<_> = store()
        .iter()
        .filter(|(kind, _, _)| kind == "task_quota")
        .cloned()
        .collect();
    let mapped_key = format!("{}/t1", std::str::from_utf8(ALICE).unwrap());
    let mapped_row = store()
        .iter()
        .find(|(kind, key, _)| kind == "task" && key == &mapped_key)
        .unwrap()
        .2
        .clone();
    let response=br#"{"jsonrpc":"2.0","id":1,"result":{"kind":"task","id":"backend-t1","contextId":"c1","status":{"state":"working"}}}"#;
    let far = piece(door, 501, Given::far_end(200, response), 65536);
    assert_eq!(far.outcome, Some(Outcome::Ready),
        "far reply did not settle (flags={}, emitted_bytes={}, publications={}, observations={}, applied={})",
        far.flags, far.emitted.len(), script(|s| s.conditional.requests.len()),
        script(|s| s.conditional.observations.len()), script(|s| s.conditional.applied));
    assert_eq!(
        script(|s| s.conditional.applied),
        applied + 2,
        "the exact backend mapping and real working transition must publish before mirroring"
    );
    assert!(
        task_state()["state"] == "working",
        "the setup holds the reported working task"
    );
    script(|s| {
        use busbar_contract::abi::sdk::plane::conditional::RecordMutation;
        let published = &s.conditional.requests[publications..];
        assert_eq!(published.len(), 2);
        let mapping = &published[0].candidate;
        assert_eq!(mapping.predicates.len(), 1);
        let predicate = &mapping.predicates[0];
        assert_eq!(door_facts::HELD_KINDS[predicate.kind as usize], "task");
        assert_eq!(predicate.key, mapped_key.as_bytes());
        assert_eq!(
            predicate.expected,
            busbar_contract::host_records::conditional::Expected::Bytes(mapped_row.clone())
        );
        assert_eq!(mapping.mutations.len(), 1);
        assert!(
            matches!(&mapping.mutations[0], RecordMutation::Put { kind, key, value }
                if *kind == predicate.kind && key == &predicate.key && value == &mapped_row),
            "backend identity rewrites the exact guarded row without advancing task state"
        );
        assert_eq!(mapping.chains.len(), 1);
        assert!(matches!(
            mapping.chains[0],
            busbar_contract::abi::sdk::plane::conditional::ChainMutation::Check { .. }
        ));
        assert!(published.iter().all(|request| request.candidate.mutations.iter().all(|mutation|
            !matches!(mutation, RecordMutation::Put { kind, .. } | RecordMutation::Delete { kind, .. }
                if door_facts::HELD_KINDS[*kind as usize] == "task_quota"))),
            "an active-to-active transition must not rewrite ready counters");
        assert!(published[1].candidate.mutations.iter().any(|m| matches!(m, RecordMutation::Put { kind, value, .. }
            if door_facts::HELD_KINDS[*kind as usize] == "task" && serde_json::from_slice::<Value>(value).unwrap()["state"] == "working")));
    });
    assert_eq!(store().iter().filter(|(kind, _, _)| kind == "task_quota").cloned().collect::<Vec<_>>(), quota_before,
        "the backend mapping and active-to-active working transition retain exact ready quota bytes");
    for key in [
        "active/v1".to_string(),
        format!("1/{}", std::str::from_utf8(ALICE).unwrap()),
    ] {
        let rows = store();
        let bytes = &rows
            .iter()
            .find(|(kind, id, _)| kind == "task_quota" && *id == key)
            .unwrap()
            .2;
        assert_eq!(
            serde_json::from_slice::<Value>(bytes).unwrap()["active"],
            1,
            "the current ready snapshot and task transition retain the exact durable active count"
        );
    }
    script(|s| {
        assert!(!s.capture_mirror && s.mirror_auth.is_none());
        s.mirror_stream = None;
        s.mirror_captures = 0;
        s.capture_mirror = true;
    });
    let create=br#"{"jsonrpc":"2.0","id":2,"method":"CreateTaskPushNotificationConfig","params":{"taskId":"t1","id":"cfg","url":"https://receiver.example/cb"}}"#;
    assert_eq!(
        door.arrive(
            502,
            ("POST", "/a2a/agents/{agent_id}"),
            "/a2a/agents/vendor",
            create
        ),
        (Outcome::Ready, 0)
    );
    assert_eq!(
        piece(door, 502, Given::attempt(b"vendor"), 65536).outcome,
        Some(Outcome::Ready)
    );
    let reply = piece(door, 502, Given::caller(create), 65536);
    assert_eq!(reply.outcome, Some(Outcome::Ready), "{reply:?}");
    assert!(
        script(|s| s.signs) > 0,
        "real config mirror must mint a callback token: {reply:?}"
    );
    let auth = script(|s| {
        assert!(
            !s.capture_mirror && s.mirror_captures == 1,
            "the current setup must capture exactly one actual mirror credential"
        );
        s.mirror_stream = None;
        s.mirror_auth
            .take()
            .expect("the current mirror supplies its callback credential")
    });
    let token = auth
        .strip_prefix("Bearer ")
        .expect("the captured scheme was checked on wire");
    assert!(
        !token.is_empty()
            && !reply
                .emitted
                .windows(token.len())
                .any(|w| w == token.as_bytes()),
        "the callback capability is never echoed to the local caller"
    );
    auth
}
#[derive(Debug)]
struct Served {
    outcome: Outcome,
    status: u32,
    needed: u64,
    diags: Vec<String>,
    writes: usize,
}

pub(super) fn copied_extensions(door: &Door, answer_head: &OutHead) -> Vec<u8> {
    let ext = answer_head.extensions;
    if ext.len == 0 {
        return Vec::new();
    }
    // SAFETY: copied while the answer's lease is live, before invoking generic RELEASE.
    let bytes = unsafe { std::slice::from_raw_parts(ext.ptr, ext.len) }.to_vec();
    if answer_head.lease != 0 {
        let input = busbar_contract::abi::mechanism::lifecycle::ReleaseIn {
            head: head::<busbar_contract::abi::mechanism::lifecycle::ReleaseIn>(
                life::RELEASE,
                Ticket::NONE,
            ),
            lease: answer_head.lease,
        };
        let mut output = out_head::<OutHead>();
        // SAFETY: existing generic RELEASE over the exact live lease returned by this instance.
        let result = unsafe {
            lifecycle().release.unwrap()(
                door.instance,
                std::ptr::from_ref(&input).cast(),
                std::ptr::from_mut(&mut output).cast(),
            )
        };
        assert_eq!(
            result.outcome(),
            Outcome::Ready,
            "conditional intent lease is released by PlaneLife"
        );
    }
    bytes
}

fn begin_conditional(ticket: Ticket, resuming: bool) -> Vec<u8> {
    script(|s| {
        let refused = s.publish_failed;
        s.conditional.begin(ticket, resuming, refused)
    })
}

fn next_conditional(
    ticket: Ticket,
    outcome: Outcome,
    short: bool,
    extensions: &[u8],
) -> Option<Vec<u8>> {
    script(|s| {
        let refused = s.publish_failed;
        s.conditional
            .returned(ticket, outcome, short, extensions, refused)
    })
}

struct Driven {
    outcome: Outcome,
    extensions: Vec<u8>,
    short: bool,
}

/// Every normal driver crossing carries the host's sticky receipt until ACK consumption.
fn sticky_settlement_driver(door: &Door, tick: bool) -> Driven {
    let receipt = script(|s| s.conditional.retained_settlement()).unwrap_or_default();
    settlement_driver(door, &receipt, tick)
}

/// The real driver ABI, including copying and releasing its leased acknowledgement.
fn settlement_driver(door: &Door, receipt: &[u8], tick: bool) -> Driven {
    let driver = ticket(1 << 29);
    let mut extensions = begin_conditional(driver, false);
    extensions.extend_from_slice(receipt);
    if tick {
        let mut input = TickIn {
            head: head::<TickIn>(life::TICK, driver),
            now_ns: 5_000_000_000,
        };
        input.head.extensions = octets(&extensions);
        let mut output: TickOut = z();
        output.head = out_head::<TickOut>();
        // SAFETY: the active Door owns this table's instance. TickIn/Out and the input's
        // extension bytes remain live through the call and copying/releasing its answer.
        // Raw driver TICK hands Pending to its driver (worker::cross_current; plane_calls::tick_copy),
        // unlike DRIVE, whose original continuation frame must remain owned below.
        let result = unsafe {
            lifecycle().tick.unwrap()(
                door.instance,
                std::ptr::from_ref(&input).cast(),
                std::ptr::from_mut(&mut output).cast(),
            )
        };
        Driven {
            outcome: result.outcome(),
            extensions: copied_extensions(door, &output.head),
            short: false,
        }
    } else {
        let (outcome, extensions, short) = door.drive_with_extensions(extensions);
        Driven {
            outcome,
            extensions,
            short,
        }
    }
}

fn consume_settlement(answer: &Driven) -> bool {
    script(|s| {
        s.conditional
            .acknowledge(&answer.extensions, answer.outcome, answer.short)
    })
}

fn serve(door: &Door, slot_id: u64, auth: &str, body: &[u8], cap: usize) -> Served {
    serve_flags(door, slot_id, auth, body, cap, 0)
}
fn recall(door: &Door, slot_id: u64, auth: &str, body: &[u8], cap: usize) -> Served {
    serve_flags(
        door,
        slot_id,
        auth,
        body,
        cap,
        busbar_contract::abi::mechanism::call::FLAG_RESUME,
    )
}
/// The existing SERVE callers retain complete semantic input and every original loan.
#[derive(Clone, Copy)]
pub(super) struct ServeGiven<'a> {
    pub(super) route: u32,
    pub(super) target: &'a [u8],
    pub(super) fields: &'a [Field],
    pub(super) body: &'a [u8],
}
struct ServeField {
    name: zeroize::Zeroizing<Vec<u8>>,
    value: zeroize::Zeroizing<Vec<u8>>,
}
pub(super) struct ServeFrame {
    pub(super) input: Box<ServeIn>,
    pub(super) output: Box<ServeOut>,
    target: zeroize::Zeroizing<Vec<u8>>,
    field_bytes: Vec<ServeField>,
    body: zeroize::Zeroizing<Vec<u8>>,
    fields: Vec<Field>,
    pub(super) reply: zeroize::Zeroizing<Vec<u8>>,
    out_fields: Vec<OutField>,
    pub(super) arena: zeroize::Zeroizing<Vec<u8>>,
    pub(super) records: Vec<RecordWrite>,
    extensions: zeroize::Zeroizing<Vec<u8>>,
}
impl ServeFrame {
    pub(super) fn new(
        slot_id: u64,
        given: ServeGiven<'_>,
        caps: (usize, usize),
        flags: u32,
    ) -> Box<Self> {
        let copy = |s: AbiStr| {
            let bytes = if s.is_empty() {
                Vec::new()
            } else {
                // SAFETY: these are the existing caller's live input Field strings, copied
                // before crossing; no caller-owned field storage is borrowed across Pending.
                unsafe { std::slice::from_raw_parts(s.ptr(), s.len()) }.to_vec()
            };
            zeroize::Zeroizing::new(bytes)
        };
        let mut frame = Box::new(Self {
            input: Box::new(z()),
            output: Box::new(z()),
            target: zeroize::Zeroizing::new(given.target.to_vec()),
            field_bytes: given
                .fields
                .iter()
                .map(|f| ServeField {
                    name: copy(f.name),
                    value: copy(f.value),
                })
                .collect(),
            body: zeroize::Zeroizing::new(given.body.to_vec()),
            fields: vec![z(); given.fields.len()],
            reply: zeroize::Zeroizing::new(vec![0; caps.0]),
            out_fields: vec![z(); 8],
            arena: zeroize::Zeroizing::new(vec![0; caps.1]),
            records: vec![z(); 64],
            extensions: zeroize::Zeroizing::new(Vec::new()),
        });
        for (field, bytes) in frame.fields.iter_mut().zip(&frame.field_bytes) {
            *field = Field {
                name: str_of(&bytes.name),
                value: str_of(&bytes.value),
            };
        }
        let input = &mut frame.input;
        input.head = head::<ServeIn>(slot::SERVE, ticket(slot_id));
        input.head.flags = flags;
        input.route = given.route;
        input.target = str_of(&frame.target);
        input.fields = frame.fields.as_ptr();
        input.fields_len = frame.fields.len();
        input.body = octets(&frame.body);
        (input.reply_buf, input.reply_cap) = (frame.reply.as_mut_ptr(), frame.reply.len());
        (input.fields_buf, input.fields_cap) =
            (frame.out_fields.as_mut_ptr(), frame.out_fields.len());
        (input.arena_buf, input.arena_cap) = (frame.arena.as_mut_ptr(), frame.arena.len());
        (input.records_buf, input.records_cap) = (frame.records.as_mut_ptr(), frame.records.len());
        frame
    }
    pub(super) fn check_resume(
        &self,
        slot_id: u64,
        given: ServeGiven<'_>,
        caps: (usize, usize),
        flags: u32,
    ) {
        let same = |s: AbiStr, held: &[u8]| {
            if s.is_empty() {
                held.is_empty()
            } else {
                // SAFETY: the re-entry's input Field strings are live for this comparison.
                (unsafe { std::slice::from_raw_parts(s.ptr(), s.len()) }) == held
            }
        };
        assert!(
            self.input.head.ticket == ticket(slot_id)
                && self.input.route == given.route
                && self.target.as_slice() == given.target
                && self.body.as_slice() == given.body
                && self.fields.len() == given.fields.len()
                && given
                    .fields
                    .iter()
                    .zip(&self.field_bytes)
                    .all(|(f, bytes)| same(f.name, &bytes.name) && same(f.value, &bytes.value))
                && self.input.head.flags & !busbar_contract::abi::mechanism::call::FLAG_RESUME
                    == flags & !busbar_contract::abi::mechanism::call::FLAG_RESUME,
            "a pending serve must resume its exact logical input"
        );
        assert_eq!(
            (self.reply.len(), self.arena.len()),
            caps,
            "pending serve loans cannot be replaced"
        );
    }
    fn extensions(&mut self, bytes: Vec<u8>) {
        // The actual loader's conditional::prepare lends receipt extensions per crossing.
        self.extensions = zeroize::Zeroizing::new(bytes);
        self.input.head.extensions = octets(&self.extensions);
    }
}

fn serve_flags(
    door: &Door,
    slot_id: u64,
    auth: &str,
    body: &[u8],
    cap: usize,
    flags: u32,
) -> Served {
    assert!(
        door.owned,
        "a borrowed door cannot own a callback continuation"
    );
    assert!(
        !door.pending.borrow().contains_key(&ticket(slot_id)),
        "a callback cannot replace a pending piece on the same full ticket"
    );
    let fields = [Field {
        name: str_of(b"authorization"),
        value: str_of(auth.as_bytes()),
    }];
    let given = ServeGiven {
        route: 2,
        target: b"/a2a/push",
        fields: &fields,
        body,
    };
    let caps = (cap, 65536);
    let resuming = {
        let pending = door.pending_serves.borrow();
        if let Some(frame) = pending.get(&ticket(slot_id)) {
            // Reject changed inputs while the original loans remain in the Door's custody.
            frame.check_resume(slot_id, given, caps, flags);
            true
        } else {
            flags & busbar_contract::abi::mechanism::call::FLAG_RESUME != 0
        }
    };
    // Keep any original Pending frame owned if the host rejects its receipt preparation.
    let extensions = begin_conditional(ticket(slot_id), resuming);
    let mut frame = door
        .pending_serves
        .borrow_mut()
        .remove(&ticket(slot_id))
        .map_or_else(
            || ServeFrame::new(slot_id, given, caps, flags),
            |mut frame| {
                frame.input.head.flags |= busbar_contract::abi::mechanism::call::FLAG_RESUME;
                frame
            },
        );
    frame.extensions(extensions);
    for crossing in 0..256 {
        *frame.output = z();
        frame.output.head = out_head::<ServeOut>();
        // SAFETY: the Door owns these exact boxed frames and all original lent allocations
        // through Pending, cancellation or synchronous CLOSE, including when host parsing fails.
        let result = unsafe {
            ops().serve.unwrap()(
                door.instance,
                std::ptr::from_ref(&*frame.input).cast(),
                std::ptr::from_mut(&mut *frame.output).cast(),
            )
        }
        .outcome();
        let head = frame.output.head;
        // Park before any fallible host processing can unwind while a loan remains outstanding.
        door.pending_serves
            .borrow_mut()
            .insert(ticket(slot_id), frame);
        let diags = if head.envelope.diags_len == 0 {
            Vec::new()
        } else {
            // SAFETY: copy the actual envelope while its answer lease is still live.
            unsafe { std::slice::from_raw_parts(head.envelope.diags, head.envelope.diags_len) }
                .iter()
                .map(|d| text(d.text))
                .collect()
        };
        let ext = copied_extensions(door, &head);
        let short = {
            let pending = door.pending_serves.borrow();
            let output = &pending[&ticket(slot_id)].output;
            if busbar_contract::abi::sdk::plane::conditional::read_request(&ext)
                .unwrap()
                .is_some()
                || busbar_contract::abi::sdk::plane::conditional::read_observation(&ext)
                    .unwrap()
                    .is_some()
            {
                assert_eq!(
                    (
                        output.status,
                        output.reply_written,
                        output.records_written,
                        output.fields_written
                    ),
                    (0, 0, 0, 0)
                );
            }
            result == Outcome::Failed && output.reply_needed > cap as u64
        };
        if let Some(next) = next_conditional(ticket(slot_id), result, short, &ext) {
            assert!(crossing < 255, "conditional callback failed to settle");
            frame = door
                .pending_serves
                .borrow_mut()
                .remove(&ticket(slot_id))
                .unwrap();
            frame.extensions(next);
            frame.input.head.flags |= busbar_contract::abi::mechanism::call::FLAG_RESUME;
            continue;
        }
        if result == Outcome::Pending {
            return Served {
                outcome: result,
                status: 0,
                needed: 0,
                diags,
                writes: 0,
            };
        }
        frame = door
            .pending_serves
            .borrow_mut()
            .remove(&ticket(slot_id))
            .unwrap();
        if result == Outcome::Ready {
            apply(
                &frame.records[..frame.output.records_written as usize],
                &frame.arena,
            );
        }
        return Served {
            outcome: result,
            status: if result == Outcome::Ready {
                frame.output.status
            } else {
                0
            },
            needed: if result == Outcome::Failed {
                frame.output.reply_needed
            } else {
                0
            },
            diags,
            writes: if result == Outcome::Ready {
                frame.output.records_written as usize
            } else {
                0
            },
        };
    }
    // The last crossing's frame is retained before this failure, including if it is Pending.
    panic!("conditional callback failed to settle");
}

fn piece(door: &Door, unit: u64, given: Given<'_>, reply_cap: usize) -> Answered {
    piece_sized(door, unit, given, reply_cap, 16, 1 << 14)
}
fn piece_sized(
    door: &Door,
    unit: u64,
    given: Given<'_>,
    reply_cap: usize,
    fields_cap: usize,
    arena_cap: usize,
) -> Answered {
    let resuming = {
        let pending = door.pending.borrow();
        if let Some(frame) = pending.get(&ticket(unit)) {
            frame.check_resume(unit, given, reply_cap, fields_cap, arena_cap);
            true
        } else {
            false
        }
    };
    let extensions = begin_conditional(ticket(unit), resuming);
    let (mut frame, _) = door.piece_frame(unit, given, reply_cap, fields_cap, arena_cap);
    frame.extensions(extensions);
    let f = ops().on_piece.expect("on_piece");
    for crossing in 0..256 {
        *frame.output = z();
        frame.output.head = out_head::<OnPieceOut>();
        // SAFETY: the same per-Door boxed frames and all original loans survive Pending;
        // only the host's authoritative receipt extension is renewed for this crossing.
        #[allow(unused_unsafe)]
        let outcome = unsafe {
            f(
                door.instance,
                std::ptr::from_ref(&*frame.input).cast(),
                std::ptr::from_mut(&mut *frame.output).cast(),
            )
        }
        .outcome();
        let head = frame.output.head;
        door.pending.borrow_mut().insert(ticket(unit), frame);
        let ext = copied_extensions(door, &head);
        let short = {
            let pending = door.pending.borrow();
            let frame = &pending[&ticket(unit)];
            let o = &frame.output;
            if outcome == Outcome::Ready {
                assert!(
                    o.emitted <= reply_cap as u64,
                    "the reply window fits its buffer"
                );
            }
            if busbar_contract::abi::sdk::plane::conditional::read_request(&ext)
                .unwrap()
                .is_some()
                || busbar_contract::abi::sdk::plane::conditional::read_observation(&ext)
                    .unwrap()
                    .is_some()
            {
                assert_eq!(
                    (
                        o.emitted,
                        o.records_written,
                        o.units_written,
                        o.flags,
                        o.fields_written
                    ),
                    (0, 0, 0, 0, 0)
                );
            }
            outcome == Outcome::Failed
                && (o.fields_needed as usize > frame.fields.len()
                    || o.arena_needed as usize > frame.arena.len()
                    || o.records_needed as usize > frame.records.len()
                    || o.units_needed as usize > frame.units.len())
        };
        if let Some(next) = next_conditional(ticket(unit), outcome, short, &ext) {
            assert!(crossing < 255, "conditional piece failed to settle");
            frame = door.pending.borrow_mut().remove(&ticket(unit)).unwrap();
            frame.extensions(next);
            frame.input.head.flags |= busbar_contract::abi::mechanism::call::FLAG_RESUME;
            continue;
        }
        if outcome == Outcome::Pending {
            return Answered {
                outcome: Some(outcome),
                ..Answered::default()
            };
        }
        frame = door.pending.borrow_mut().remove(&ticket(unit)).unwrap();
        if outcome == Outcome::Ready {
            apply(
                &frame.records[..frame.output.records_written as usize],
                &frame.arena,
            );
        }
        return frame.answer(outcome);
    }
    panic!("conditional piece failed to settle");
}

const WORKING: &[u8] = br#"{"id":"t1","status":{"state":"working"}}"#;
const COMPLETED: &[u8] = br#"{"id":"t1","status":{"state":"completed"}}"#;
fn fault(reply: &Served) {
    assert_eq!(
        (reply.outcome, reply.status),
        (Outcome::Ready, 503),
        "{reply:?}"
    );
    assert_eq!(
        reply
            .diags
            .iter()
            .filter(|d| d.contains("BUSBAR-7050"))
            .count(),
        1,
        "{reply:?}"
    );
    assert_eq!(reply.writes, 0);
}
#[test]
fn callback_signer_read_and_transition_faults_are_retryable_and_distinct_from_bad_tokens() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let (_reset, door) = open_scripted();
    let auth = registered(&door);
    assert_eq!(
        serve(&door, 600, "Bearer missing.00", WORKING, 4096).status,
        401
    );
    script(|s| s.sign_failed = true);
    fault(&serve(&door, 601, &auth, WORKING, 4096));
    script(|s| s.sign_failed = false);
    script(|s| s.read_failed = true);
    fault(&serve(&door, 602, &auth, WORKING, 4096));
    script(|s| s.read_failed = false);
    script(|s| s.publish_failed = true);
    fault(&serve(&door, 603, &auth, COMPLETED, 4096));
    script(|s| s.publish_failed = false);
    let unchanged = serve(&door, 604, &auth, WORKING, 4096);
    assert_eq!(unchanged.status, 202);
    assert_eq!(unchanged.writes, 0);
    let illegal = serve(
        &door,
        605,
        &auth,
        br#"{"status":{"state":"submitted"}}"#,
        4096,
    );
    assert_eq!(illegal.status, 202);
    assert_eq!(illegal.writes, 0);
    store().retain(|(kind, _, _)| kind != "task");
    assert_eq!(serve(&door, 606, &auth, WORKING, 4096).status, 401);
}
#[test]
fn a_pending_push_retains_its_original_timestamp_across_the_publication_receipts() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let (_reset, door) = open_scripted();
    let auth = registered(&door);
    let before = script(|s| s.conditional.events.len());
    script(|s| {
        s.wall_ns = 1_800_000_010_000_000_000;
        s.clock_step_ns = 1_000_000_000;
    });
    let answer = serve(&door, 699, &auth, COMPLETED, 4096);
    assert_eq!(
        (answer.outcome, answer.status),
        (Outcome::Ready, 202),
        "{answer:?}"
    );
    assert_eq!(task_state()["state"], "completed");
    assert_eq!(task_state()["updated_at"], 1_800_000_010_u64);
    assert!(script(|s| s.wall_ns) > 1_800_000_000_000_000_000);
    assert_eq!(script(|s| s.conditional.events.len()), before + 1);
    assert!(!door.pending_serves.borrow().contains_key(&ticket(699)));
}

#[test]
fn callback_pending_and_short_refusals_preserve_one_budget_charge_and_one_warning() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let (_reset, door) = open_scripted();
    let auth = registered(&door);
    script(|s| s.read_pending = true);
    assert_eq!(
        serve(&door, 700, &auth, WORKING, 4096).outcome,
        Outcome::Pending
    );
    let loans = || {
        let pending = door.pending_serves.borrow();
        let frame = &pending[&ticket(700)];
        [
            std::ptr::from_ref(&*frame.input) as usize,
            std::ptr::from_ref(&*frame.output) as usize,
            frame.input.body.ptr as usize,
            frame.input.fields as usize,
            frame.fields[0].value.ptr() as usize,
            frame.input.reply_buf as usize,
            frame.input.fields_buf as usize,
            frame.input.arena_buf as usize,
            frame.input.records_buf as usize,
        ]
    };
    let original = loans();
    for (body, cap) in [(COMPLETED, 4096), (WORKING, 8192)] {
        let refusal = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            recall(&door, 700, &auth, body, cap)
        }))
        .expect_err("changed push input must be refused by the fixture");
        let message = refusal
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| refusal.downcast_ref::<&str>().copied())
            .unwrap_or("");
        let expected = if cap == 4096 {
            "a pending serve must resume its exact logical input"
        } else {
            "pending serve loans cannot be replaced"
        };
        assert!(message.contains(expected), "{message}");
        assert_eq!(
            loans(),
            original,
            "invalid re-entry cannot release pending loans"
        );
    }
    assert_eq!(
        recall(&door, 700, &auth, WORKING, 4096).outcome,
        Outcome::Pending
    );
    assert_eq!(
        loans(),
        original,
        "actual Pending recall preserves every original loan"
    );
    script(|s| s.read_pending = false);
    assert_eq!(recall(&door, 700, &auth, WORKING, 4096).status, 202);
    assert!(!door.pending_serves.borrow().contains_key(&ticket(700)));

    for ticket in 701..759 {
        assert_eq!(serve(&door, ticket, &auth, WORKING, 4096).status, 202);
    }
    script(|s| s.read_failed = true);
    let short = serve(&door, 759, &auth, WORKING, 0);
    assert_eq!(short.outcome, Outcome::Failed);
    assert!(short.needed > 0);
    assert_eq!(
        short
            .diags
            .iter()
            .filter(|d| d.contains("BUSBAR-7050"))
            .count(),
        0,
        "SHORT preflight emits no warning before a complete response fits"
    );
    // Terminal SHORT is a fresh same-ticket call; only Pending permits FLAG_RESUME.
    let recalled = serve(&door, 759, &auth, WORKING, 4096);
    assert_eq!(
        (recalled.outcome, recalled.status),
        (Outcome::Ready, 503),
        "{recalled:?}"
    );
    assert_eq!(
        recalled
            .diags
            .iter()
            .filter(|d| d.contains("BUSBAR-7050"))
            .count(),
        1,
        "the complete fresh refusal emits exactly one warning"
    );
    script(|s| s.read_failed = false);
    assert_eq!(serve(&door, 760, &auth, WORKING, 4096).status, 429);
    let short_limit = serve(&door, 761, &auth, WORKING, 0);
    assert_eq!(short_limit.outcome, Outcome::Failed);
    assert!(short_limit.needed > 0);
    let recalled_limit = serve(&door, 761, &auth, WORKING, 4096);
    assert_eq!(
        (recalled_limit.outcome, recalled_limit.status),
        (Outcome::Ready, 429)
    );
}

#[test]
fn failed_config_read_keeps_the_accepted_move_and_retries_its_notification() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let (_reset, door) = open_scripted();
    let auth = registered(&door);
    let before_applied = script(|s| s.conditional.applied);
    script(|s| s.config_failed = true);
    let accepted = serve(&door, 800, &auth, COMPLETED, 4096);
    assert_eq!(
        (accepted.outcome, accepted.status),
        (Outcome::Ready, 202),
        "{accepted:?}"
    );
    assert_eq!(
        accepted.writes, 0,
        "guarded mutations never ride ordinary output"
    );
    assert_eq!(script(|s| s.conditional.applied), before_applied + 1);
    let row = store()
        .iter()
        .find(|(kind, _, _)| kind == "task")
        .unwrap()
        .2
        .clone();
    assert_eq!(
        serde_json::from_slice::<Value>(&row).unwrap()["state"],
        "completed"
    );
    assert!(accepted.diags.iter().any(|d| d.contains("BUSBAR-7050")));
    let before = script(|s| s.config_gets);
    script(|s| s.config_failed = false);
    let (outcome, _) = door.tick();
    assert_eq!(outcome, Outcome::Ready);
    assert!(
        script(|s| s.config_gets) > before,
        "driver must retry the retained configuration read"
    );
}
#[test]
fn repeated_actual_submits_do_not_repeat_a_full_retention_read() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let (_reset, door) = open_scripted();
    assert_eq!(door.connect("vendor").1, 200);
    let request=br#"{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"message":{"messageId":"m","role":"user","parts":[{"kind":"text","text":"hello"}]}}}"#;
    let mut first = 0;
    for unit in [901, 902] {
        assert_eq!(
            door.arrive(
                unit,
                ("POST", "/a2a/agents/{agent_id}"),
                "/a2a/agents/vendor",
                request
            ),
            (Outcome::Ready, 0)
        );
        assert_eq!(
            piece(&door, unit, Given::attempt(b"vendor"), 65536).outcome,
            Some(Outcome::Ready)
        );
        let sent = piece(&door, unit, Given::caller(request), 65536);
        assert_eq!(sent.outcome, Some(Outcome::Ready), "{sent:?}");
        assert!(
            !sent.emitted.is_empty(),
            "actual message must reach the relay"
        );
        if unit == 901 {
            first = script(|s| s.full_lists);
            assert!(first > 0);
        } else {
            assert_eq!(
                script(|s| s.full_lists),
                first,
                "second submit inside the gate must not list every task again"
            );
        }
    }
}

#[test]
fn malformed_callback_short_recall_keeps_its_refusal_and_single_charge() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let (_reset, door) = open_scripted();
    let auth = registered(&door);
    for id in 1000..1059 {
        assert_eq!(serve(&door, id, &auth, WORKING, 4096).status, 202);
    }
    let short = serve(&door, 1059, &auth, b"{", 0);
    assert_eq!(short.outcome, Outcome::Failed);
    assert!(short.needed > 0);
    let recalled = serve(&door, 1059, &auth, b"{", 4096);
    assert_eq!(
        (recalled.outcome, recalled.status),
        (Outcome::Ready, 400),
        "{recalled:?}"
    );
    assert_eq!(serve(&door, 1060, &auth, WORKING, 4096).status, 429);
}

fn task_state() -> Value {
    let rows = store();
    serde_json::from_slice(
        &rows
            .iter()
            .find(|(kind, key, _)| kind == "task" && key.ends_with("/t1"))
            .unwrap()
            .2,
    )
    .unwrap()
}

#[test]
fn conditional_callback_waits_for_applied_and_replays_the_identical_candidate() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let (_reset, door) = open_scripted();
    let auth = registered(&door);
    let applied = script(|s| s.conditional.applied);
    let emitted = script(|s| s.conditional.emitted.len());
    script(|s| s.conditional.pause_commit = true);
    let waiting = serve(&door, 1100, &auth, COMPLETED, 4096);
    assert_eq!(
        (waiting.outcome, waiting.status, waiting.writes),
        (Outcome::Pending, 0, 0)
    );
    assert_eq!(task_state()["state"], "working");
    let reads = script(|s| s.gets);
    assert_eq!(
        recall(&door, 1100, &auth, COMPLETED, 4096).outcome,
        Outcome::Pending
    );
    assert_eq!(
        script(|s| s.gets),
        reads,
        "a wake without the receipt cannot reread or replan"
    );
    assert_eq!(script(|s| s.conditional.applied), applied);
    script(|s| {
        assert_eq!(
            s.conditional.emitted[emitted],
            s.conditional.emitted[emitted + 1]
        );
    });
    assert_eq!(
        serve(&door, 1101, &auth, WORKING, 4096).status,
        202,
        "pending terminal publication has not ended the callback token"
    );
    script(|s| s.conditional.pause_commit = false);
    let landed = recall(&door, 1100, &auth, COMPLETED, 4096);
    assert_eq!(
        (landed.outcome, landed.status, landed.writes),
        (Outcome::Ready, 202, 0)
    );
    assert_eq!(script(|s| s.conditional.applied), applied + 1);
    assert_eq!(task_state()["state"], "completed");
    assert_eq!(
        serve(&door, 1102, &auth, WORKING, 4096).status,
        401,
        "the acknowledged terminal move ends its token"
    );
    assert_eq!(
        script(|s| s.claims),
        0,
        "publication does not leave a TTL claim behind"
    );
}

#[test]
fn conditional_conflict_observes_again_and_reads_a_fresh_row() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let (_reset, door) = open_scripted();
    let auth = registered(&door);
    let before = script(|s| s.conditional.requests.len());
    let observed = script(|s| s.conditional.observations.len());
    script(|s| s.conditional.conflict_once = true);
    assert_eq!(serve(&door, 1110, &auth, COMPLETED, 4096).status, 202);
    script(|s| {
        let attempts = &s.conditional.requests[before..];
        assert_eq!(attempts.len(), 2);
        assert_ne!(
            attempts[0].candidate.correlation,
            attempts[1].candidate.correlation
        );
        assert_ne!(
            attempts[0].candidate.predicates[0].expected,
            attempts[1].candidate.predicates[0].expected,
            "the real competing cursor change is reread"
        );
        assert_eq!(s.conditional.observations.len(), observed + 2);
        let epoch = attempts[0].capability.epoch;
        let reads: Vec<_> = s
            .conditional
            .reads
            .iter()
            .filter(|r| r.0 == epoch && r.2 == "task")
            .collect();
        assert!(
            reads.len() >= 3,
            "precheck plus two distinct post-observation GET handles: {reads:?}"
        );
        assert!(reads.windows(2).all(|r| r[0].1 < r[1].1));
    });
    assert_eq!(
        task_state()["artifact_cursor"],
        1,
        "the retry preserves the competitor's mutation"
    );
    assert_eq!(task_state()["state"], "completed");
}

#[test]
fn lost_applied_callback_receipt_never_reexecutes_the_transaction() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let (_reset, door) = open_scripted();
    let auth = registered(&door);
    let applied = script(|s| s.conditional.applied);
    let emitted = script(|s| s.conditional.emitted.len());
    script(|s| s.conditional.lose_applied_once = true);
    assert_eq!(serve(&door, 1120, &auth, COMPLETED, 4096).status, 202);
    script(|s| {
        assert_eq!(s.conditional.applied, applied + 1);
        assert_eq!(s.conditional.emitted.len(), emitted + 2);
        assert_eq!(
            s.conditional.emitted[emitted],
            s.conditional.emitted[emitted + 1]
        );
    });
}

const SUBMIT: &[u8] = br#"{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"message":{"messageId":"m","role":"user","parts":[{"kind":"text","text":"hello"}]}}}"#;
fn arrive_submit(door: &Door, unit: u64) {
    assert_eq!(
        door.arrive(
            unit,
            ("POST", "/a2a/agents/{agent_id}"),
            "/a2a/agents/vendor",
            SUBMIT
        )
        .0,
        Outcome::Ready
    );
}

#[test]
fn an_applied_task_open_keeps_its_identity_through_output_short_recall() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let (_reset, door) = open_scripted();
    assert_eq!(door.connect("vendor").1, 200);
    arrive_submit(&door, 1130);
    let attempt = piece(&door, 1130, Given::attempt(b"vendor"), 65536);
    assert_eq!(
        attempt.outcome,
        Some(Outcome::Ready),
        "flags={}, emitted_bytes={}",
        attempt.flags,
        attempt.emitted.len()
    );
    assert_ne!(attempt.flags & busbar_contract::abi::plane::EMIT_TO_FAR_END, 0,
        "the setup must actually open its task (flags={}, emitted_bytes={}, publications={}, observations={})",
        attempt.flags, attempt.emitted.len(), script(|s| s.conditional.requests.len()), script(|s| s.conditional.observations.len()));
    let applied = script(|s| s.conditional.applied);
    let rows = store().clone();
    let short = piece_sized(&door, 1130, Given::caller(SUBMIT), 65536, 16, 0);
    assert_eq!(short.outcome, Some(Outcome::Failed));
    assert!(
        short.arena_needed > 0,
        "the auxiliary arena causes an actual SHORT"
    );
    let recalled = piece(&door, 1130, Given::caller(SUBMIT), 65536);
    assert_eq!(recalled.outcome, Some(Outcome::Ready));
    assert!(!recalled.emitted.is_empty());
    assert_eq!(*store(), rows, "SHORT writes no second task or chain event");
    script(|s| {
        assert_eq!(s.conditional.applied, applied);
        assert_eq!(
            s.conditional.events.len(),
            2,
            "submitted and delegated are one atomic opening"
        );
        assert_eq!(s.claims, 0);
    });
}

#[test]
fn an_applied_task_open_streams_a_zero_room_body_without_reopening_the_task() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let (_reset, door) = open_scripted();
    assert_eq!(door.connect("vendor").1, 200);
    arrive_submit(&door, 1131);
    let attempt = piece(&door, 1131, Given::attempt(b"vendor"), 65536);
    assert_eq!(attempt.outcome, Some(Outcome::Ready));
    assert_ne!(
        attempt.flags & busbar_contract::abi::plane::EMIT_TO_FAR_END,
        0
    );
    let applied = script(|s| s.conditional.applied);
    let rows = store().clone();
    let blocked = piece(&door, 1131, Given::caller(SUBMIT), 0);
    assert_eq!(blocked.outcome, Some(Outcome::Ready));
    assert_eq!(blocked.more, 1);
    assert!(blocked.emitted.is_empty());
    let drained = piece(&door, 1131, Given::more(), 65536);
    assert_eq!(drained.outcome, Some(Outcome::Ready));
    assert_eq!(drained.more, 0);
    assert!(!drained.emitted.is_empty());
    assert_eq!(*store(), rows);
    script(|s| {
        assert_eq!(s.conditional.applied, applied);
        assert_eq!(s.conditional.events.len(), 2);
        assert_eq!(s.claims, 0);
    });
}

#[test]
fn cancel_starts_no_publication_and_does_not_replace_a_submitted_attempt() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let (_reset, door) = open_scripted();
    assert_eq!(door.connect("vendor").1, 200);
    arrive_submit(&door, 1140);
    assert_eq!(door.cancel_unit(1140), Outcome::Ready);
    assert_eq!(script(|s| s.conditional.applied), 0);
    arrive_submit(&door, 1141);
    script(|s| s.conditional.pause_commit = true);
    let pending = piece(&door, 1141, Given::attempt(b"vendor"), 65536);
    assert_eq!(pending.outcome, Some(Outcome::Pending));
    assert!(pending.emitted.is_empty());
    assert_eq!(pending.flags, 0);
    let loans = || {
        let pending = door.pending.borrow();
        let frame = &pending[&ticket(1141)];
        [
            std::ptr::from_ref(&*frame.input) as usize,
            std::ptr::from_ref(&*frame.output) as usize,
            frame.input.member.ptr() as usize,
            frame.input.bytes.ptr as usize,
            frame.input.reply_buf as usize,
            frame.input.fields_buf as usize,
            frame.input.arena_buf as usize,
            frame.input.records_buf as usize,
            frame.input.units_buf as usize,
        ]
    };
    let original_loans = loans();
    assert_eq!(
        piece(&door, 1141, Given::attempt(b"vendor"), 65536).outcome,
        Some(Outcome::Pending)
    );
    assert_eq!(
        loans(),
        original_loans,
        "paused conditional piece keeps its original frame"
    );
    assert_eq!(door.cancel_unit(1141), Outcome::Ready);
    assert!(!door.pending.borrow().contains_key(&ticket(1141)));
    let original = script(|s| s.conditional.emitted.last().unwrap().clone());
    script(|s| {
        s.conditional.pause_commit = false;

        s.conditional.begin(ticket(1141), true, false);
        assert_eq!(s.conditional.requests.last(), Some(&original));
        assert_eq!(s.conditional.applied, 1);
    });
    let cancelled = piece(&door, 1141, Given::attempt(b"vendor"), 65536);
    assert_eq!(cancelled.outcome, Some(Outcome::Failed));
    assert!(cancelled.emitted.is_empty());
    assert_eq!(script(|s| s.conditional.applied), 1);
    assert_eq!(script(|s| s.claims), 0);
}

#[test]
fn canceled_raw_callback_settles_late_applied_once_across_lost_driver_ack() {
    use busbar_contract::abi::sdk::plane::conditional as wire;
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let (_reset, door) = open_scripted();
    let auth = registered(&door);

    assert_eq!(door.tick().0, Outcome::Ready);
    assert_eq!(door.tick().0, Outcome::Ready);
    let notifications = script(|s| s.notifications);
    let applied = script(|s| s.conditional.applied);
    script(|s| s.conditional.pause_commit = true);
    assert_eq!(
        serve(&door, 1200, &auth, COMPLETED, 4096).outcome,
        Outcome::Pending
    );
    let original = script(|s| s.conditional.emitted.last().unwrap().clone());
    assert!(door.pending_serves.borrow().contains_key(&ticket(1200)));
    assert_eq!(door.cancel_unit(1200), Outcome::Ready);
    assert!(!door.pending_serves.borrow().contains_key(&ticket(1200)));
    let reads = script(|s| s.gets);
    let emitted = script(|s| s.conditional.emitted.len());
    let receipt = script(|s| s.conditional.detach(ticket(1200)));
    assert_eq!(
        script(|s| s.conditional.requests.last().cloned()),
        Some(original.clone())
    );
    assert_eq!(script(|s| s.conditional.applied), applied + 1);
    assert_eq!(script(|s| s.notifications), notifications);

    assert_eq!(
        recall(&door, 1200, &auth, COMPLETED, 4096).outcome,
        Outcome::Failed
    );
    assert_eq!(
        script(|s| (s.gets, s.conditional.emitted.len())),
        (reads, emitted)
    );
    let first = sticky_settlement_driver(&door, false);
    assert_eq!(first.outcome, Outcome::Pending);
    let driver_loans = || {
        let driver = door.driver.borrow();
        let frame = driver.as_ref().unwrap();
        assert!(frame.pending);
        [
            std::ptr::from_ref(&*frame.input) as usize,
            std::ptr::from_ref(&*frame.output) as usize,
            frame.input.sessions_buf as usize,
        ]
    };
    let original_driver_loans = driver_loans();
    assert!(wire::read_settlement_ack(&first.extensions)
        .unwrap()
        .unwrap()
        .matches(&original)
        .unwrap());

    assert_eq!(
        script(|s| s.conditional.retained_settlement()),
        Some(receipt.clone())
    );
    assert_eq!(serve(&door, 1201, &auth, WORKING, 4096).status, 401);
    let repeated = sticky_settlement_driver(&door, true);
    assert_eq!(repeated.outcome, Outcome::Pending);
    assert_eq!(first.extensions, repeated.extensions);
    let repeated_drive = sticky_settlement_driver(&door, false);
    assert_eq!(repeated_drive.outcome, Outcome::Pending);
    assert_eq!(
        driver_loans(),
        original_driver_loans,
        "DRIVE resumes its original frames and sessions loan after the TICK handoff"
    );
    assert_ne!(
        door.driver
            .borrow()
            .as_ref()
            .unwrap()
            .input
            .drive
            .head
            .flags
            & busbar_contract::abi::mechanism::call::FLAG_RESUME,
        0
    );
    assert_eq!(first.extensions, repeated_drive.extensions);
    assert_eq!(
        script(|s| s.notifications),
        notifications,
        "sticky receipt retries are ACK-only; delivery waits for host ACK consumption"
    );
    assert!(consume_settlement(&repeated_drive));
    assert_eq!(script(|s| s.conditional.retained_settlement()), None);
    assert_eq!(
        sticky_settlement_driver(&door, false).outcome,
        Outcome::Ready
    );
    assert_eq!(
        sticky_settlement_driver(&door, true).outcome,
        Outcome::Ready
    );
    assert_eq!(script(|s| s.notifications), notifications + 1);
    assert_eq!(
        sticky_settlement_driver(&door, true).outcome,
        Outcome::Ready
    );
    assert_eq!(
        script(|s| s.notifications),
        notifications + 1,
        "repeated receipt consumption queues exactly one notification"
    );

    let stale = settlement_driver(&door, &receipt, false);
    assert_eq!(stale.outcome, Outcome::Failed);
    assert!(wire::read_settlement_ack(&stale.extensions)
        .unwrap()
        .is_none());
    assert_eq!(script(|s| s.notifications), notifications + 1);
    assert_eq!(
        script(|s| (s.conditional.applied, s.conditional.acknowledgements)),
        (applied + 1, 1)
    );
}

#[test]
fn detached_settlement_rejects_other_instance_changed_identity_and_reused_ticket() {
    use busbar_contract::abi::sdk::plane::conditional as wire;
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let (_reset, door) = open_scripted();
    let auth = registered(&door);
    script(|s| s.conditional.pause_commit = true);
    assert_eq!(
        serve(&door, 1210, &auth, COMPLETED, 4096).outcome,
        Outcome::Pending
    );
    assert_eq!(door.cancel_unit(1210), Outcome::Ready);
    let receipt = script(|s| s.conditional.detach(ticket(1210)));
    let original = script(|s| s.conditional.emitted.last().unwrap().clone());
    let other = open_scripted_instance();
    let foreign = settlement_driver(&other, &receipt, false);
    assert_eq!(foreign.outcome, Outcome::Failed);
    assert!(wire::read_settlement_ack(&foreign.extensions)
        .unwrap()
        .is_none());
    assert!(!consume_settlement(&foreign));
    for changed in 0..5 {
        let mut request = original.clone();
        match changed {
            0 => request.capability.ticket.generation += 1,
            1 => request.capability.epoch += 1,
            2 => request.candidate.correlation += 1,
            3 => request
                .candidate
                .mutations
                .push(wire::RecordMutation::Delete {
                    kind: 0,
                    key: b"wrong-digest".to_vec(),
                }),
            _ => request.capability.ticket.slot += 1,
        }
        let wrong = wire::encode_settlement(
            &request,
            &wire::ConditionalResult {
                correlation: request.candidate.correlation,
                decision: Ok(busbar_contract::host_records::conditional::Decision::Applied),
            },
        )
        .unwrap();
        let answer = settlement_driver(&door, &wrong, changed % 2 == 0);
        assert_eq!(answer.outcome, Outcome::Failed);
        assert!(wire::read_settlement_ack(&answer.extensions)
            .unwrap()
            .is_none());
        assert!(!consume_settlement(&answer));
        assert_eq!(
            script(|s| s.conditional.retained_settlement()),
            Some(receipt.clone())
        );
    }
    let emitted = script(|s| s.conditional.emitted.len());
    assert_eq!(
        recall(&door, 1210, &auth, COMPLETED, 4096).outcome,
        Outcome::Failed
    );
    assert_eq!(script(|s| s.conditional.emitted.len()), emitted);
    let exact = settlement_driver(&door, &receipt, false);
    assert_eq!(exact.outcome, Outcome::Pending);
    assert!(consume_settlement(&exact));
}

#[test]
fn actual_short_callback_then_cancel_retains_original_receipt_until_driver_ack() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let (_reset, door) = open_scripted();
    registered(&door);
    let applied = script(|s| s.conditional.applied);
    let publications = script(|s| s.conditional.requests.len());
    let mapped_key = format!("{}/t1", std::str::from_utf8(ALICE).unwrap());
    let mapped_row = store()
        .iter()
        .find(|(kind, key, _)| kind == "task" && key == &mapped_key)
        .unwrap()
        .2
        .clone();
    let events = script(|s| s.conditional.events.len());
    let short = get_task_answer_sized(&door, 1220, 0, true);
    assert_eq!(short.outcome, Some(Outcome::Failed));
    assert!(short.emitted.is_empty());
    assert!(short.fields_needed > 0);
    assert_eq!(script(|s| s.conditional.applied), applied + 2);
    // A reported backend identity has its own guarded mapping publication before the
    // terminal transition. SHORT and its later settlement must replay neither one.
    script(|s| {
        use busbar_contract::abi::sdk::plane::conditional::RecordMutation;
        let published = &s.conditional.requests[publications..];
        assert_eq!(published.len(), 2);
        let mapping = &published[0].candidate;
        assert_eq!(mapping.predicates.len(), 1);
        let predicate = &mapping.predicates[0];
        assert_eq!(door_facts::HELD_KINDS[predicate.kind as usize], "task");
        assert_eq!(predicate.key, mapped_key.as_bytes());
        assert_eq!(
            predicate.expected,
            busbar_contract::host_records::conditional::Expected::Bytes(mapped_row.clone())
        );
        assert_eq!(mapping.mutations.len(), 1);
        assert!(
            matches!(&mapping.mutations[0], RecordMutation::Put { kind, key, value }
                if *kind == predicate.kind && key == &predicate.key && value == &mapped_row),
            "backend identity rewrites the exact guarded row without advancing task state"
        );
        assert_eq!(mapping.chains.len(), 1);
        assert!(matches!(
            mapping.chains[0],
            busbar_contract::abi::sdk::plane::conditional::ChainMutation::Check { .. }
        ));
        assert!(published[1].candidate.mutations.iter().any(|m| matches!(m, RecordMutation::Put { kind, value, .. }
            if door_facts::HELD_KINDS[*kind as usize] == "task" && serde_json::from_slice::<Value>(value).unwrap()["state"] == "completed")));
        assert_eq!(s.conditional.events.len(), events + 1);
    });
    assert_eq!(task_state()["state"], "completed");
    assert_eq!(script(|s| s.conditional.acknowledgements), 0);
    assert_eq!(door.cancel_unit(1220), Outcome::Ready);
    let receipt = script(|s| s.conditional.detach(ticket(1220)));
    let ack = settlement_driver(&door, &receipt, true);
    assert_eq!(ack.outcome, Outcome::Pending);
    assert_eq!(
        script(|s| s.conditional.retained_settlement()),
        Some(receipt)
    );
    assert!(consume_settlement(&ack));
    assert_eq!(
        script(|s| (s.conditional.applied, s.conditional.acknowledgements)),
        (applied + 2, 1)
    );
    assert_eq!(script(|s| s.conditional.events.len()), events + 1);
}

fn get_task_answer_sized(door: &Door, unit: u64, cap: usize, short: bool) -> Answered {
    get_named_task_answer(door, unit, "t1", "completed", cap, short)
}
fn get_named_task_answer(
    door: &Door,
    unit: u64,
    task_id: &str,
    state: &str,
    cap: usize,
    short: bool,
) -> Answered {
    let request = serde_json::to_vec(
        &json!({"jsonrpc":"2.0","id":1,"method":"GetTask","params":{"id":task_id}}),
    )
    .unwrap();
    assert_eq!(
        door.arrive(
            unit,
            ("POST", "/a2a/agents/{agent_id}"),
            "/a2a/agents/vendor",
            &request
        ),
        (Outcome::Ready, 0)
    );
    assert_eq!(
        piece(door, unit, Given::attempt(b"vendor"), 65536).outcome,
        Some(Outcome::Ready)
    );
    assert_eq!(
        piece(door, unit, Given::caller(&request), 65536).outcome,
        Some(Outcome::Ready)
    );
    let response = serde_json::to_vec(&json!({"jsonrpc":"2.0","id":1,"result":{"id":format!("backend-{task_id}"),"contextId":"c1","status":{"state":state}}})).unwrap();
    piece_sized(
        door,
        unit,
        Given::far_end(200, &response),
        cap,
        if short { 0 } else { 16 },
        if short { 0 } else { 1 << 14 },
    )
}

/// tasks::suffix writes exactly six length-prefixed fields, without the host chain prelude.
/// Decode every field so a malformed event cannot silently disappear from the count or pause.
fn task_event_kind(mut content: &[u8]) -> &str {
    let mut kind = None;
    for index in 0..6 {
        let (length, rest) = content
            .split_first_chunk::<8>()
            .expect("a task event field has its complete length prefix");
        let length = usize::try_from(u64::from_be_bytes(*length))
            .expect("a task event field length fits this host");
        let (field, rest) = rest
            .split_at_checked(length)
            .expect("a task event field has its complete declared payload");
        if index == 0 {
            assert_eq!(field.len(), 8, "a task event timestamp is eight bytes");
        } else {
            let text =
                std::str::from_utf8(field).expect("a task event's declared text fields are UTF-8");
            if index == 1 {
                kind = Some(text);
            }
        }
        content = rest;
    }
    assert!(content.is_empty(), "a task event has exactly six fields");
    kind.expect("the event kind is the second field")
}

#[test]
fn task_event_kind_reads_the_declared_suffix_and_rejects_malformed_fields() {
    // Independent literal for timestamp=1, kind, context, principal, agent and state.
    let valid = b"\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\x13task.push_delivered\0\0\0\0\0\0\0\x02c1\0\0\0\0\0\0\0\x06caller\0\0\0\0\0\0\0\x06vendor\0\0\0\0\0\0\0\x07working";
    assert_eq!(task_event_kind(valid), "task.push_delivered");
    let mut other_kind = valid.to_vec();
    other_kind[42] = b'X';
    assert_ne!(task_event_kind(&other_kind), "task.push_delivered");
    let mut wrong_timestamp = valid.to_vec();
    wrong_timestamp[..8].copy_from_slice(&7_u64.to_be_bytes());
    let mut oversized = valid.to_vec();
    oversized[..8].copy_from_slice(&u64::MAX.to_be_bytes());
    let mut bad_kind = valid.to_vec();
    bad_kind[24] = 0xff;
    let mut bad_state = valid.to_vec();
    *bad_state.last_mut().unwrap() = 0xff;
    let mut trailing = valid.to_vec();
    trailing.push(0);
    for malformed in [
        valid[..7].to_vec(),
        valid[..valid.len() - 1].to_vec(),
        valid[..valid.len() - 15].to_vec(),
        wrong_timestamp,
        oversized,
        bad_kind,
        bad_state,
        trailing,
    ] {
        assert!(
            std::panic::catch_unwind(|| task_event_kind(&malformed)).is_err(),
            "malformed relevant event framing must fail rather than be skipped"
        );
    }
}

fn delivered_events() -> usize {
    script(|s| {
        s.conditional
            .events
            .iter()
            .filter(|(_, content)| task_event_kind(content) == "task.push_delivered")
            .count()
    })
}

#[test]
fn canceled_owed_append_is_acknowledged_only_after_its_exact_late_applied() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let (_reset, door) = open_scripted();
    let auth = registered(&door);
    seed_task("t2", "working");
    assert_eq!(serve(&door, 1230, &auth, COMPLETED, 4096).status, 202);
    assert_eq!(door.tick().0, Outcome::Ready);
    assert_eq!(door.tick().0, Outcome::Ready);
    assert!(
        script(|s| s.notifications) > 0,
        "an actual receiver exchange creates the owed delivery outcome"
    );
    let before = delivered_events();
    script(|s| s.conditional.pause_owed_commit = true);
    let pending = get_named_task_answer(&door, 1231, "t2", "working", 65536, false);
    assert_eq!(pending.outcome, Some(Outcome::Pending));
    assert_eq!(delivered_events(), before);
    let original = script(|s| s.conditional.emitted.last().unwrap().clone());
    assert_eq!(original.capability.ticket, ticket(1231));
    assert!(
        original.candidate.chains.iter().any(|chain| matches!(chain,
        busbar_contract::abi::sdk::plane::conditional::ChainMutation::Append { kind, scope, content, .. }
        if door_facts::HELD_KINDS.get(*kind as usize) == Some(&"task_event")
            && scope == format!("{}/t1", std::str::from_utf8(ALICE).unwrap()).as_bytes()
            && task_event_kind(content) == "task.push_delivered"))
    );
    assert!(
        script(|s| !s.conditional.requests.contains(&original)),
        "the actual owed append is copied but paused before the host decision"
    );
    assert_eq!(door.cancel_unit(1231), Outcome::Ready);
    let receipt = script(|s| s.conditional.detach(ticket(1231)));
    assert_eq!(
        script(|s| s.conditional.retained_settlement()),
        Some(receipt)
    );
    assert_eq!(delivered_events(), before + 1);
    let ack = sticky_settlement_driver(&door, false);
    assert_eq!(ack.outcome, Outcome::Pending);
    let repeated = sticky_settlement_driver(&door, true);
    assert_eq!(repeated.outcome, Outcome::Pending);
    assert_eq!(ack.extensions, repeated.extensions);
    assert!(consume_settlement(&repeated));
    assert_eq!(
        sticky_settlement_driver(&door, false).outcome,
        Outcome::Ready
    );
    assert_eq!(
        get_named_task_answer(&door, 1232, "t2", "working", 65536, false).outcome,
        Some(Outcome::Ready)
    );
    assert_eq!(
        delivered_events(),
        before + 1,
        "settlement consumes the exact owed receipt so a later real callback cannot file it again"
    );
    assert_eq!(
        script(|s| s
            .conditional
            .requests
            .iter()
            .filter(|request| **request == original)
            .count()),
        1
    );
}
