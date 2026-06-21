//! src/commandline/s_09_list_wallets.rs
//! 9. List wallets (CLI DB)
//!
//! This module isolates wallet listing into its own struct + impl,
//! while keeping private CommandManager access inside the manager wrapper.

use crate::utility::alpha_002_error_detection_system::ErrorDetection;
use crate::utility::logging_data::JsonLogger;
use colored::Colorize;
use std::path::Path;

pub struct S09ListWallets;

impl S09ListWallets {
    pub fn new() -> Self {
        Self
    }

    // ─────────────────────────────────────────────────────────────────────
    // 9) List wallets (CLI DB)
    // ─────────────────────────────────────────────────────────────────────
    pub fn list_wallets(&self, json_logger: &JsonLogger) -> Result<(), ErrorDetection> {
        use crate::utility::helper::{REMZAR_WALLET_LEN, canon_wallet_id_checked};
        use std::fs;
        use std::io::{self, Write};

        println!("{}", "🔹 Listing all wallets...".cyan());

        // Prompt to proceed
        print!(
            "{}",
            "💼 Do you want to display your wallets? (yes/no): ".yellow()
        );
        io::stdout().flush().map_err(|e| {
            let msg = format!("Failed to flush stdout: {}", e);
            json_logger
                .log_error_event("wallet", "ListWalletsFlushStdoutFailed", &msg)
                .ok();
            ErrorDetection::IoError {
                message: msg,
                code: None,
                source: None,
            }
        })?;

        let mut response = String::new();
        io::stdin().read_line(&mut response).map_err(|e| {
            let msg = format!("Failed to read input: {}", e);
            json_logger
                .log_error_event("wallet", "ListWalletsReadConfirmInputFailed", &msg)
                .ok();
            ErrorDetection::IoError {
                message: msg,
                code: None,
                source: None,
            }
        })?;

        if response.trim().to_lowercase() != "yes" {
            println!("{}", "❌ Returning to the menu.".red());
            return Ok(()); // user cancelled → not an error
        }

        // Prompt for wallet directory
        print!(
            "{}",
            "📂 Enter the directory path where your wallet files are stored: ".yellow()
        );
        io::stdout().flush().map_err(|e| {
            let msg = format!("Failed to flush stdout: {}", e);
            json_logger
                .log_error_event(
                    "wallet",
                    "ListWalletsFlushStdoutWalletDirPromptFailed",
                    &msg,
                )
                .ok();
            ErrorDetection::IoError {
                message: msg,
                code: None,
                source: None,
            }
        })?;

        let mut wallet_dir = String::new();
        io::stdin().read_line(&mut wallet_dir).map_err(|e| {
            let msg = format!("Failed to read wallet directory: {}", e);
            json_logger
                .log_error_event("wallet", "ListWalletsReadWalletDirInputFailed", &msg)
                .ok();
            ErrorDetection::IoError {
                message: msg,
                code: None,
                source: None,
            }
        })?;

        // Basic stdin DoS guard: reject absurdly large paths
        const MAX_WALLET_DIR_INPUT: usize = 4096;
        if wallet_dir.len() > MAX_WALLET_DIR_INPUT {
            let msg = format!(
                "❌ Directory path is too long (max {} chars).",
                MAX_WALLET_DIR_INPUT
            );
            json_logger
                .log_error_event("wallet", "ListWalletsWalletDirTooLong", &msg)
                .ok();
            return Err(ErrorDetection::ValidationError {
                message: msg,
                tx_id: None,
            });
        }

        let wallet_dir = wallet_dir.trim();
        if wallet_dir.is_empty() || !Path::new(wallet_dir).exists() {
            let msg = "❌ The specified directory does not exist.".to_string();
            json_logger
                .log_error_event("wallet", "ListWalletsWalletDirNotExist", &msg)
                .ok();
            return Err(ErrorDetection::ValidationError {
                message: msg,
                tx_id: None,
            });
        }

        // Read directory & list wallet files
        let wallet_files = fs::read_dir(wallet_dir).map_err(|e| {
            let msg = format!("❌ Failed to read the directory {}: {}", wallet_dir, e);
            json_logger
                .log_error_event("wallet", "ListWalletsReadDirFailed", &msg)
                .ok();
            ErrorDetection::IoError {
                message: msg,
                code: None,
                source: None,
            }
        })?;

        // DoS guard: cap how many entries we iterate
        const MAX_DIR_ENTRIES_SCAN: usize = 25_000;
        // Optional: cap how many wallet addresses we print
        const MAX_WALLETS_PRINT: usize = 10_000;

        let mut found_wallets = false;

        // Header width aligned to canonical wallet length
        println!(
            "{:<width$}",
            "Wallet Address".cyan(),
            width = REMZAR_WALLET_LEN
        );
        println!("{}", "-".repeat(REMZAR_WALLET_LEN.saturating_add(6)));

        let mut scanned: usize = 0;
        let mut printed: usize = 0;

        for entry_res in wallet_files {
            scanned = scanned.saturating_add(1);
            if scanned > MAX_DIR_ENTRIES_SCAN {
                let msg = format!(
                    "⚠️ Stopped scanning after {} entries (directory too large).",
                    MAX_DIR_ENTRIES_SCAN
                );
                println!("{}", msg.yellow());
                json_logger
                    .log_error_event("wallet", "ListWalletsDirScanCapped", &msg)
                    .ok();
                break;
            }

            let entry = entry_res.map_err(|e| {
                let msg = format!(
                    "❌ Error accessing a file in directory {}: {}",
                    wallet_dir, e
                );
                json_logger
                    .log_error_event("wallet", "ListWalletsDirEntryError", &msg)
                    .ok();
                ErrorDetection::IoError {
                    message: msg,
                    code: None,
                    source: None,
                }
            })?;

            // Skip non-files
            let ft = entry.file_type().map_err(|e| {
                let msg = format!("❌ Failed to read file type in {}: {}", wallet_dir, e);
                json_logger
                    .log_error_event("wallet", "ListWalletsFileTypeReadFailed", &msg)
                    .ok();
                ErrorDetection::IoError {
                    message: msg,
                    code: None,
                    source: None,
                }
            })?;
            if !ft.is_file() {
                continue;
            }

            let file_path = entry.path();
            if file_path.extension().is_some_and(|ext| ext == "wallet") {
                found_wallets = true;

                // STRICT: wallet filename stem must be valid UTF-8
                let wallet_address = match file_path.file_stem().and_then(|os| os.to_str()) {
                    Some(s) => s.to_string(),
                    None => {
                        let msg =
                            "⚠️ Skipping wallet file: filename is not valid UTF-8.".to_string();
                        println!("{}", msg.yellow());
                        json_logger
                            .log_error_event("wallet", "ListWalletsWalletFilenameNonUtf8", &msg)
                            .ok();
                        continue;
                    }
                };

                // Validate + canonicalize wallet format
                let canon = match canon_wallet_id_checked(&wallet_address) {
                    Ok(c) => c,
                    Err(err) => {
                        println!("{}", format!("⚠️ Invalid wallet address: {}", err).yellow());
                        json_logger
                            .log_error_event(
                                "wallet",
                                "ListWalletsInvalidWalletFilename",
                                &err.to_string(),
                            )
                            .ok();
                        continue;
                    }
                };

                // Enforce canonical filenames
                if canon != wallet_address {
                    let msg = format!(
                        "⚠️ Skipping non-canonical wallet filename (expected canonical): {}",
                        wallet_address
                    );
                    println!("{}", msg.yellow());
                    json_logger
                        .log_error_event("wallet", "ListWalletsNonCanonicalWalletFilename", &msg)
                        .ok();
                    continue;
                }

                printed = printed.saturating_add(1);
                if printed > MAX_WALLETS_PRINT {
                    let msg = format!(
                        "⚠️ Stopped printing after {} wallets (output capped).",
                        MAX_WALLETS_PRINT
                    );
                    println!("{}", msg.yellow());
                    json_logger
                        .log_error_event("wallet", "ListWalletsWalletPrintCapped", &msg)
                        .ok();
                    break;
                }

                println!("{}", canon.green());
            }
        }

        if !found_wallets {
            println!(
                "{}",
                "⚠️ No wallet files found in the specified directory.".yellow()
            );
        } else {
            println!("{}", "✅ Wallets listed successfully.".green());
        }

        Ok(())
    }
}

impl Default for S09ListWallets {
    fn default() -> Self {
        Self::new()
    }
}
