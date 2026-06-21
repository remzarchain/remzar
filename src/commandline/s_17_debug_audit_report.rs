//! src/commandline/s_17_debug_audit_report.rs

use crate::runtime::p2p_006_sync_runtime::NodeOpts;
use crate::storage::rocksdb_000_directory::DirectoryDB;
use crate::utility::alpha_002_error_detection_system::ErrorDetection;
use crate::utility::audit_report_001_hub::AuditReport;
use crate::utility::logging_data::JsonLogger;
use colored::Colorize;
use std::io::{self, Write};
use std::path::Path;

/// Section 17: Debug Audit Report.
pub struct S17DebugAuditReport;

impl S17DebugAuditReport {
    pub fn new() -> Self {
        Self
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 17. Debug: Audit Report (interactive wrapper)
    // ─────────────────────────────────────────────────────────────────────────────
    pub fn debug_audit_report(
        &mut self,
        opts: &NodeOpts,
        json_logger: &JsonLogger,
    ) -> Result<(), ErrorDetection> {
        loop {
            print!("Do you want to audit your blockchain? (yes/no): ");
            io::stdout().flush().ok();
            let mut yn = String::new();
            io::stdin().read_line(&mut yn).ok();
            match yn.trim().to_lowercase().as_str() {
                "yes" | "y" => {
                    let directories =
                        DirectoryDB::from_node_opts(opts).map_err(ErrorDetection::from)?;
                    match directories.create_audit_reports_directory() {
                        Ok(()) => {
                            println!(
                                "✅ Audit reports directory is ready: {}",
                                directories.audit_reports_path.display()
                            );
                        }
                        Err(e) => {
                            println!(
                                "❌ Failed to set up audit reports directory: {}\nAborting audit.",
                                e
                            );
                            return Err(ErrorDetection::from(e));
                        }
                    }
                    break;
                }
                "no" | "n" => return Ok(()),
                _ => println!("{}", "⚠️  Enter yes or no.".yellow()),
            }
        }

        // Directory Path prompt (for output)
        let directory_path = loop {
            print!("Enter the directory path where you want to store the audit reports: ");
            io::stdout().flush().ok();
            let mut input = String::new();
            io::stdin().read_line(&mut input).ok();
            let dir = input.trim();
            if Path::new(dir).exists() {
                break dir.to_string();
            } else {
                println!(
                    "{}",
                    "⚠️  Invalid directory path. Please enter an existing directory.".yellow()
                );
            }
        };

        // Blockchain DB Path prompt (the important part!)
        let blockchain_db_path = loop {
            print!(
                "Enter the FULL path to your blockchain database folder (e.g. C:/Users/You/AppData/.../002.blockchain_db): "
            );
            io::stdout().flush().ok();
            let mut input = String::new();
            io::stdin().read_line(&mut input).ok();
            let db_path = input.trim();
            if Path::new(db_path).exists() {
                break db_path.to_string();
            } else {
                println!(
                    "{}",
                    "⚠️  Invalid path. Please enter an existing database folder.".yellow()
                );
            }
        };

        // Block-range prompt
        let (start, end) = loop {
            println!();
            print!(
                "Enter block index or range (e.g. 42 or 100-150, or 100250-100500, max span 250): "
            );
            io::stdout().flush().ok();
            let mut input = String::new();
            io::stdin().read_line(&mut input).ok();
            let s = input.trim();

            if let Ok(idx) = s.parse::<u64>() {
                break (idx, idx);
            }

            if let Some((a, b)) = s.split_once('-')
                && let (Ok(s0), Ok(e0)) = (a.trim().parse::<u64>(), b.trim().parse::<u64>())
                && s0 <= e0
                && e0.saturating_sub(s0) <= 250
            {
                break (s0, e0);
            }

            println!(
                "{}",
                "⚠️  Invalid input—must be N or N-M with M–N ≤ 250.".yellow()
            );
        };

        // Format selector
        println!();
        println!("{}", "Select audit export format:".cyan());
        println!("  {} Export as JSON", "1)".yellow());
        println!("  {} Export as PDF", "2)".yellow());
        println!("  {} Back to menu", "3)".yellow());

        let json_path = format!("{}/audit_report.json", directory_path);
        let pdf_path = format!("{}/audit_report.pdf", directory_path);

        loop {
            print!("\n⏳ Enter choice (1–3): ");
            io::stdout().flush().ok();

            let mut choice = String::new();
            io::stdin().read_line(&mut choice).ok();

            match choice.trim() {
                "1" => match AuditReport::load_range_with_path(&blockchain_db_path, start, end) {
                    Ok(rpt) => {
                        if let Err(e) = rpt.export_json(&json_path) {
                            let msg = format!("Export JSON failed: {}", e);
                            json_logger
                                .log_error_event("audit", "ExportJsonFailed", &msg)
                                .ok();
                            return Err(e);
                        }
                        println!("{}", format!("✅ Wrote {}.", json_path).green());
                        break;
                    }
                    Err(e) => {
                        json_logger
                            .log_error_event("audit", "LoadRangeFailed", &e.to_string())
                            .ok();
                        return Err(e);
                    }
                },
                "2" => match AuditReport::load_range_with_path(&blockchain_db_path, start, end) {
                    Ok(rpt) => {
                        if let Err(e) = rpt.export_pdf(&pdf_path) {
                            let msg = format!("Export PDF failed: {}", e);
                            json_logger
                                .log_error_event("audit", "ExportPdfFailed", &msg)
                                .ok();
                            return Err(e);
                        }
                        println!("{}", format!("✅ Wrote {}.", pdf_path).green());
                        break;
                    }
                    Err(e) => {
                        json_logger
                            .log_error_event("audit", "LoadRangeFailed", &e.to_string())
                            .ok();
                        return Err(e);
                    }
                },
                "3" => {
                    println!("{}", "🚪 Returning to main menu…".red());
                    break;
                }
                _ => println!("{}", "⚠️  Enter 1, 2, or 3.".yellow()),
            }
        }

        // Exit prompt
        println!("{}", "🚪 Exiting the audit generator.".red());
        Ok(())
    }
}

impl Default for S17DebugAuditReport {
    fn default() -> Self {
        Self::new()
    }
}
