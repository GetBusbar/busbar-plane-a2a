// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE gRPC LINE'S MESSAGES, generated from the a2aproject's own `a2a.proto` (vendored verbatim in

use std::error::Error;
use std::path::PathBuf;

#[path = "build/custody.rs"]
mod custody;

const PROTO_FILES: &[&str] = &["proto/a2a.proto"];
const PROTO_INCLUDES: &[&str] = &["proto"];
const PROTOJSON_PACKAGES: &[&str] = &[".lf.a2a.v1"];

/// The repeated members a `null` reads as empty for (`a2a-pb`'s own patch list).
const NULL_REPEATED: &[&str] = &[
    "extensions",
    "supported_interfaces",
    "security_requirements",
    "default_input_modes",
    "default_output_modes",
    "skills",
    "signatures",
    "tags",
    "examples",
    "input_modes",
    "output_modes",
    "parts",
    "reference_task_ids",
    "accepted_output_modes",
    "list",
    "configs",
    "tasks",
    "artifacts",
    "history",
];

const NULL_MAP: (&str, &str) = (
    "map_.next_value::<std::collections::HashMap<_, _>>()?",
    "map_.next_value::<Option<std::collections::HashMap<_, _>>>()?.unwrap_or_default()",
);

/// How many map fields the vendored proto has: the null-map patch must match each.
const NULL_MAP_FIELDS: usize = 7;

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-changed=proto");

    let path = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?)
        .join("tests/data/method-inventory.json");
    println!("cargo:rerun-if-changed={}", path.display());
    let text = std::fs::read_to_string(&path)?;
    std::fs::write(
        PathBuf::from(std::env::var("OUT_DIR")?).join("method_inventory.rs"),
        format!(
            "/// `tests/data/method-inventory.json`, read at build time.\n\
             pub(crate) const METHOD_INVENTORY: &str = {text:?};\n"
        ),
    )?;

    println!(
        "cargo::metadata=cells={}",
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?)
            .join("tests/root/mod.rs")
            .display()
    );

    println!(
        "cargo::metadata=blackbox={}",
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?)
            .join("tests/blackbox")
            .display()
    );
    println!("cargo:rerun-if-changed=tests/blackbox");
    let out_dir = PathBuf::from(std::env::var("OUT_DIR")?);
    let descriptor_path = out_dir.join("a2a-descriptor.bin");
    let mut config = prost_build::Config::new();
    config
        .prost_path("crate::proto::custody::prost")
        .protoc_executable(protoc_bin_vendored::protoc_bin_path()?)
        .out_dir(&out_dir)
        .file_descriptor_set_path(&descriptor_path)
        .compile_well_known_types()
        .extern_path(".google.protobuf", "crate::wkt");
    config.compile_protos(PROTO_FILES, PROTO_INCLUDES)?;

    let descriptor_set = std::fs::read(&descriptor_path)?;
    pbjson_build::Builder::new()
        .out_dir(&out_dir)
        .register_descriptors(&descriptor_set)?
        .build(PROTOJSON_PACKAGES)?;

    let serde_path = out_dir.join("lf.a2a.v1.serde.rs");
    let mut generated = std::fs::read_to_string(&serde_path)?;

    let proto = std::fs::read_to_string(PROTO_FILES[0])?;
    let maps = generated.matches(NULL_MAP.0).count();
    if maps != NULL_MAP_FIELDS {
        return Err(format!(
            "the null-map patch matched {maps} map field(s), not the vendored proto's {NULL_MAP_FIELDS}"
        )
        .into());
    }
    generated = generated.replace(NULL_MAP.0, NULL_MAP.1);
    for member in NULL_REPEATED {
        let needle = format!("{member}__ = Some(map_.next_value()?);");
        let patch =
            format!("{member}__ = Some(map_.next_value::<Option<_>>()?.unwrap_or_default());");
        let (patched, hits) = replace_whole(&generated, &needle, &patch);
        let declared = repeated_fields(&proto, member);
        if declared == 0 || hits != declared {
            return Err(format!(
                "the null-repeated patch for `{member}` matched {hits} field(s), not the vendored \
                 proto's {declared}"
            )
            .into());
        }
        generated = patched;
    }
    std::fs::write(serde_path, custody::serde(&generated)?)?;
    let messages_path = out_dir.join("lf.a2a.v1.rs");
    let messages = std::fs::read_to_string(&messages_path)?;
    std::fs::write(messages_path, custody::messages(&messages)?)?;
    Ok(())
}

/// How many fields named `name` the proto source `proto` declares `repeated`: every line

fn repeated_fields(proto: &str, name: &str) -> usize {
    proto
        .lines()
        .filter(|line| {
            let mut words = line.split_whitespace();
            words.next() == Some("repeated")
                && words.next().is_some()
                && words
                    .next()
                    .is_some_and(|field| field.split('=').next() == Some(name))
        })
        .count()
}

/// `text` with every `needle` that starts a whole identifier replaced by `with`, and how many were:

fn replace_whole(text: &str, needle: &str, with: &str) -> (String, usize) {
    let mut out = String::with_capacity(text.len());
    let (mut at, mut hits) = (0, 0);
    while let Some(found) = text[at..].find(needle) {
        let start = at + found;
        let whole = text[..start]
            .chars()
            .next_back()
            .is_none_or(|c| !(c.is_ascii_alphanumeric() || c == '_'));
        out.push_str(&text[at..start]);
        if whole {
            out.push_str(with);
            hits += 1;
        } else {
            out.push_str(needle);
        }
        at = start + needle.len();
    }
    out.push_str(&text[at..]);
    (out, hits)
}
