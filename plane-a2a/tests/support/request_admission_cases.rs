// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Actual Arrive slot admission, before task records or a backend wire exist.
use super::*;

const LIMIT: usize = 256 * 1024;

fn refused_before_decoding(door: &Door, unit: u64, route: &str, target: &str, body: &[u8]) {
    let mut input: ArriveIn = z();
    input.head = head::<ArriveIn>(slot::ARRIVE, Ticket::NONE);
    input.unit = unit;
    input.claim = claim("POST", route);
    input.target = str_of(target.as_bytes());
    input.method = str_of(b"POST");
    input.body = octets(body);
    let mut units = [z::<UnitCount>(); 8];
    (input.units_buf, input.units_cap) = (units.as_mut_ptr(), units.len());
    let mut output: ArriveOut = z();
    output.head = out_head::<ArriveOut>();
    // SAFETY: complete live Arrive ABI input, output, and borrowed body/unit buffers.
    let result = unsafe {
        ops().arrive.unwrap()(
            door.instance,
            std::ptr::from_ref(&input).cast(),
            std::ptr::from_mut(&mut output).cast(),
        )
    };
    assert_eq!(
        (result.outcome(), output.refusal_status),
        (Outcome::Refused, 400),
        "{route}"
    );
    assert!(!output.head.error.is_empty());
    // SAFETY: the slot's refusal text remains owned by the live door until the next call.
    let words =
        unsafe { std::slice::from_raw_parts(output.head.error.ptr(), output.head.error.len()) };
    let words = std::str::from_utf8(words).unwrap();
    assert!(
        words.contains("262144-byte admission limit"),
        "size refusal before decoder: {route}: {words}"
    );
    assert!(words.contains("-32602"), "invalid parameters: {words}");
}

#[test]
fn request_admission_rejects_before_composition_tasks_and_dispatch() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    store().clear();
    let door = open();
    let records = store().clone();
    let next_wire = NEXT_WIRE.load(Ordering::SeqCst);
    let service_calls = handles().len();
    let oversized = vec![b'!'; LIMIT + 1];
    for (unit, route, target) in [
        (1801, "/a2a/agents/{agent_id}", "/a2a/agents/vendor"),
        (1802, "/a2a/message:send", "/a2a/message:send"),
        (
            1803,
            "/lf.a2a.v1.A2AService/{method}",
            "/lf.a2a.v1.A2AService/SendMessage",
        ),
    ] {
        refused_before_decoding(&door, unit, route, target, &oversized);
    }
    assert_eq!(*store(), records, "no task or quota publication");
    assert_eq!(
        handles().len(),
        service_calls,
        "no host service side effects"
    );
    assert_eq!(
        NEXT_WIRE.load(Ordering::SeqCst),
        next_wire,
        "no backend dispatch"
    );
    let (outcome, status, body) = door.connect("vendor");
    assert_eq!((outcome, status), (Outcome::Ready, 200), "{body}");
    let mut exact = br#"{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"message":{"messageId":"boundary","role":"ROLE_USER","parts":[{"text":"hi"}]}}}"#.to_vec();
    exact.resize(LIMIT, b' ');
    assert_eq!(
        door.arrive(
            1804,
            ("POST", "/a2a/agents/{agent_id}"),
            "/a2a/agents/vendor",
            &exact
        ),
        (Outcome::Ready, 0)
    );
    exact.push(b' ');
    assert_eq!(
        door.arrive(
            1805,
            ("POST", "/a2a/agents/{agent_id}"),
            "/a2a/agents/vendor",
            &exact
        ),
        (Outcome::Refused, 400)
    );
}
