//! utility/audit_report_003_json.rs

use serde::Serialize;
use serde_json::ser::{PrettyFormatter, Serializer};
use std::io;

use crate::utility::{
    alpha_001_global_configuration::GlobalConfiguration,
    audit_report_001_hub::{AuditBlock, AuditReport},
};

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
struct AuditMeta<'a> {
    chain_id: &'a str,
    guardian_id: &'a str,
    report_time: i64,
    export_time: i64,
    block_span: u64,
    total_tx: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
struct AuditJson<'a> {
    meta: AuditMeta<'a>,
    blocks: &'a [AuditBlock],
}

/// Build *canonical* JSON (pretty-printed with 4-space indents) and return the bytes.
pub fn build_json(report: &AuditReport, total_tx: u64, export_time: i64) -> io::Result<Vec<u8>> {
    // ---- meta ------------------------------------------------------------
    let span = report.blocks.len() as u64;
    let snapshot_ts = report
        .blocks
        .first()
        .map(|b| i64::try_from(b.timestamp).unwrap_or(i64::MAX))
        .unwrap_or(0);

    let meta = AuditMeta {
        chain_id: GlobalConfiguration::COIN_NAME,
        guardian_id: GlobalConfiguration::GENESIS_VALIDATOR,
        report_time: snapshot_ts,
        export_time, // ← now tracked
        block_span: span,
        total_tx,
    };

    let root = AuditJson {
        meta,
        blocks: &report.blocks,
    };

    // Serialize with pretty formatter using 4-space indent
    let mut buf = Vec::new();
    let formatter = PrettyFormatter::with_indent(b"    ");
    let mut ser = Serializer::with_formatter(&mut buf, formatter);
    root.serialize(&mut ser).map_err(io::Error::other)?;
    Ok(buf)
}
