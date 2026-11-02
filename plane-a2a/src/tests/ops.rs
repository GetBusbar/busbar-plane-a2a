//! Tests for `ops.rs`. Lifted out of the implementation file so its line count

use super::{row_for, MethodRow, METHODS, OP_CLASSES};

/// Every method maps to a class the plane declares.
#[test]
fn every_method_names_a_declared_class() {
    for row in METHODS {
        assert!(
            OP_CLASSES.contains(&row.op),
            "method {} names an undeclared class {}",
            row.method,
            row.op
        );
    }
}

/// No method name appears twice, so a lookup has one answer.
#[test]
fn no_method_name_is_repeated() {
    for (i, row) in METHODS.iter().enumerate() {
        assert!(
            !METHODS[..i].iter().any(|r| r.method == row.method),
            "method {} is listed twice",
            row.method
        );
    }
}

/// Both spellings of one operation agree on its class and on whether it streams.
#[test]
fn the_two_spellings_of_an_operation_agree() {
    for row in METHODS {
        let partner: Vec<&MethodRow> = METHODS
            .iter()
            .filter(|r| r.op == row.op && r.wording != row.wording)
            .collect();
        assert_eq!(
            partner.len(),
            1,
            "{} has {} partner spellings, not one",
            row.method,
            partner.len()
        );
        assert_eq!(
            partner[0].multi_frame, row.multi_frame,
            "the two spellings of {} disagree on multi_frame",
            row.op
        );
    }
}

/// The lookup is total over the table and answers nothing else.
#[test]
fn the_lookup_answers_the_table_and_nothing_else() {
    for row in METHODS {
        assert_eq!(row_for(row.method), Some(row));
    }
    assert_eq!(row_for("tasks/incinerate"), None);
    assert_eq!(row_for(""), None);

    assert_eq!(row_for("MESSAGE/SEND"), None);
}

/// Every multi-frame method is one of the two the codec's own multi-frame test recognises.
#[test]
fn the_multi_frame_set_matches_the_codecs_own_rule() {
    for row in METHODS {
        let by_the_codecs_rule = row.method.ends_with("/stream")
            || row.method == "tasks/resubscribe"
            || row.method == "SendStreamingMessage"
            || row.method == "SubscribeToTask";
        assert_eq!(
            row.multi_frame, by_the_codecs_rule,
            "{} disagrees with the codec's multi_frame rule",
            row.method
        );
    }
}
