// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE gRPC LINE'S MESSAGES, generated from the a2aproject's own `a2a.proto` (vendored verbatim in
//! `proto/`, with the minimal `google.api` option stubs it imports, from the `a2a-pb` 0.2.0 crate,
//! Apache-2.0), as `a2a-pb` generated them: the prost messages with the well-known types mapped to
//! the plane's own (`crate::wkt`, `pbjson-types`' mapping without its calendar crate), and pbjson's
//! ProtoJSON serde for the `lf.a2a.v1` package, patched as `a2a-pb`
//! patched it so a JSON `null` for a repeated or map member reads as empty (ARCHITECT ruling Q1 (C),
//! 2026-10-04: the plane generates its messages; no gRPC server stack in a plane's closure).

use std::error::Error;
use std::path::PathBuf;

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

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-changed=proto");
    // THE METHOD INVENTORY a unit test holds the plane's JSON-RPC names to: busbar's
    // `qa/method-inventory.json` at `.busbar-ref`, read HERE, at build time, from the busbar
    // checkout plugin CI exports (`BUSBAR_CHECKOUT`), and included by the test as generated source,
    // so no test of the plane reads the environment or a file at run time. Unset (a build that is
    // not CI, busbar's own workspace build), it is `None` and the test refuses.
    println!("cargo:rerun-if-env-changed=BUSBAR_CHECKOUT");
    let inventory = match std::env::var_os("BUSBAR_CHECKOUT") {
        Some(busbar) => {
            let path = PathBuf::from(busbar).join("qa/method-inventory.json");
            println!("cargo:rerun-if-changed={}", path.display());
            Some(std::fs::read_to_string(&path)?)
        }
        None => None,
    };
    let body = inventory.map_or_else(|| "None".to_string(), |text| format!("Some({text:?})"));
    std::fs::write(
        PathBuf::from(std::env::var("OUT_DIR")?).join("method_inventory.rs"),
        format!(
            "/// busbar's `qa/method-inventory.json` at `.busbar-ref`, read at build time; `None` when\n\
             /// the build had no busbar checkout.\n\
             pub(crate) const METHOD_INVENTORY: Option<&str> = {body};\n"
        ),
    )?;
    // THE ROOT CELLS' ADDRESS (this crate's `links` row): the composition root compiles this
    // plane's own root cells from here, reading it as `DEP_BUSBAR_DOOR_CELLS_<CRATE>_CELLS`.
    println!(
        "cargo::metadata=cells={}",
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?)
            .join("tests/root/mod.rs")
            .display()
    );
    // THE BLACK-BOX CASES' ADDRESS (the same `links` row): the root's black-box runner boots the
    // real binary against every case file here, reading it as `DEP_BUSBAR_DOOR_CELLS_<CRATE>_BLACKBOX`.
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
    generated = generated.replace(NULL_MAP.0, NULL_MAP.1);
    for member in NULL_REPEATED {
        generated = generated.replace(
            &format!("{member}__ = Some(map_.next_value()?);"),
            &format!("{member}__ = Some(map_.next_value::<Option<_>>()?.unwrap_or_default());"),
        );
    }
    std::fs::write(serde_path, generated)?;
    Ok(())
}
