//! tests/file_genesis_file_tests.rs

#![cfg(test)]

use remzar::blockchain::genesis_001_block::GenesisBlock;
use remzar::blockchain::genesis_002_file::GenesisFile;
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;

use serde_json::json;
use std::fs::{OpenOptions, create_dir_all};
use std::io::Write;
use std::path::Path;

#[test]
#[ignore]
fn export_genesis_json_for_chain() {
    // Explicit opt-in so CI / accidental runs don't export chain artifacts.
    if std::env::var("REMZAR_GENESIS_EXPORT").as_deref() != Ok("YES") {
        eprintln!("Skipping: set REMZAR_GENESIS_EXPORT=YES to export genesis.json.");
        return;
    }

    // Deterministic timestamp for reproducible genesis.json across all nodes
    let ts = GlobalConfiguration::DEFAULT_USER_CHAIN_GENESIS_TIMESTAMP;

    // 1) Build GenesisBlock (CURRENT schema: NO por_view, NO miner)
    let genesis_block = GenesisBlock::new_with_timestamp(
        "Genesis for Remzar Blockchain - A PQ L1 base layer for verified data",
        ts,
    )
    .expect("Failed to create GenesisBlock");

    // 2) Build GenesisFile using the CURRENT schema
    let genesis_file: GenesisFile = serde_json::from_value(json!({
        "chain_id": "remzar-06-26-26-v1",
        "description": "remzar blockchain",
        "version": "1.0.0",
        "genesis_block": genesis_block
    }))
    .expect("Failed to build GenesisFile from JSON value");

    // 2.5) Validate before export (paranoia)
    genesis_file
        .validate()
        .expect("GenesisFile validation failed");

    // 3) Write to target/genesis.json (refuse overwrite)
    create_dir_all("target").expect("Unable to create target/ directory");

    let out_path = "target/genesis.json";
    assert!(
        !Path::new(out_path).exists(),
        "Refusing to overwrite: {out_path} already exists"
    );

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true) // <- atomic: fail if file already exists
        .open(out_path)
        .expect("Failed to create target/genesis.json (already exists?)");

    serde_json::to_writer_pretty(&mut file, &genesis_file)
        .expect("Failed to serialize GenesisFile to JSON");
    file.write_all(b"\n")
        .expect("Failed to write trailing newline");

    // 4) Assert file exists
    assert!(Path::new(out_path).exists());

    println!("✅ Exported genesis.json to: {out_path}");
}
