//! Repeated arrival requests return the same disposition.

/// The door's arrival gives the same answer every time it is asked the same question.
#[test]
fn the_arrival_is_deterministic() {
    let bodies: Vec<Vec<u8>> = crate::ops::OP_CLASSES
        .iter()
        .filter_map(|op| crate::ops::METHODS.iter().find(|r| r.op == *op))
        .map(|row| {
            format!(
                r#"{{"jsonrpc":"2.0","id":5,"method":"{}","params":{{"id":"t1"}}}}"#,
                row.method
            )
            .into_bytes()
        })
        .collect();

    assert!(
        !bodies.is_empty(),
        "no request body was derived from the declared op classes, so nothing was driven twice"
    );
    for body in &bodies {
        let answers: Vec<String> = (0..8)
            .map(|_| {
                format!(
                    "{:?}",
                    crate::agent_arrival::decide_and_read(body, |_| None).0
                )
            })
            .collect();
        assert!(
            answers.windows(2).all(|w| w[0] == w[1]),
            "the arrival varied over one body: {answers:?}"
        );
    }
}
