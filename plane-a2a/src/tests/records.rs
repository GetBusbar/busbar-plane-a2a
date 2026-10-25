//! Tests for `records.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

use super::{RECORD_SCHEMAS, SCHEMA_TASK, SCHEMA_TASK_EVENT};

/// The two durable schemas carry the codec's own record kind names.
///
/// If the codec renames a kind, this goes red rather than the plane quietly writing records
/// under a name nothing reads back.
#[test]
fn the_durable_schemas_are_the_codecs_own_kinds() {
    assert_eq!(SCHEMA_TASK.as_str(), crate::records::KIND_TASK);
    assert_eq!(SCHEMA_TASK_EVENT.as_str(), crate::records::KIND_TASK_EVENT);
}

/// No schema name is repeated.
#[test]
fn no_schema_is_declared_twice() {
    for (i, schema) in RECORD_SCHEMAS.iter().enumerate() {
        assert!(
            !RECORD_SCHEMAS[..i].iter().any(|s| s == schema),
            "{schema} is declared twice"
        );
    }
}

/// The kind the door declares chained is the task-event kind, at its index in the tail's kinds.
#[test]
fn the_chained_kind_is_the_task_event_kind() {
    assert_eq!(
        crate::records::HELD_KINDS[crate::records::TASK_EVENT_INDEX as usize],
        crate::records::KIND_TASK_EVENT
    );
}
