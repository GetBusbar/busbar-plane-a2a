// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

fn arrive_with_field(door: &Door, unit: u64, name: &[u8], value: &[u8]) -> (Outcome, u32) {
    let fields = [Field {
        name: str_of(name),
        value: str_of(value),
    }];
    let mut i: ArriveIn = z();
    i.head = head::<ArriveIn>(slot::ARRIVE, Ticket::NONE);
    i.unit = unit;
    i.claim = claim("POST", "/a2a/agents/{agent_id}");
    i.target = str_of(b"/a2a/agents/vendor");
    i.method = str_of(b"POST");
    i.body = octets(CARD_READ);
    (i.fields, i.fields_len) = (fields.as_ptr(), fields.len());
    let mut units = [z::<UnitCount>(); 8];
    (i.units_buf, i.units_cap) = (units.as_mut_ptr(), units.len());
    let mut o: ArriveOut = z();
    o.head = out_head::<ArriveOut>();
    let arrive = ops().arrive.unwrap();
    // SAFETY: the door's published ABI slot receives live input/output and field buffers.
    #[allow(unused_unsafe)]
    let ret = unsafe {
        arrive(
            door.instance,
            std::ptr::from_ref(&i).cast(),
            std::ptr::from_mut(&mut o).cast(),
        )
    };
    (ret.outcome(), o.refusal_status)
}

#[test]
fn unreadable_request_headers_refuse_instead_of_becoming_absent() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let door = open();
    let (outcome, status, body) = door.connect("vendor");
    assert_eq!((outcome, status), (Outcome::Ready, 200), "{body}");
    let invalid = b"\xffrequest-secret";
    for (unit, name, status) in [
        (801, b"A2A-Version".as_slice(), 400),
        (802, b"Content-Type".as_slice(), 415),
        (803, b"Origin".as_slice(), 403),
    ] {
        assert_eq!(
            arrive_with_field(&door, unit, name, invalid),
            (Outcome::Refused, status)
        );
    }
    assert_eq!(
        door.arrive(
            804,
            ("POST", "/a2a/agents/{agent_id}"),
            "/a2a/agents/vendor",
            CARD_READ
        ),
        (Outcome::Ready, 0)
    );
    for (unit, name, value) in [
        (805, b"A2A-Version".as_slice(), b"1.0".as_slice()),
        (
            806,
            b"Content-Type".as_slice(),
            b"application/json".as_slice(),
        ),
        (807, b"Origin".as_slice(), b"http://localhost".as_slice()),
    ] {
        assert_eq!(
            arrive_with_field(&door, unit, name, value),
            (Outcome::Ready, 0)
        );
    }
}
