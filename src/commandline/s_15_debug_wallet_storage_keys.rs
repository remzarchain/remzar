//! src/commandline/s_15_debug_wallet_storage_keys.rs

use crate::cryptography::ml_dsa_65_005_encryption::Cryption;
use crate::utility::alpha_002_error_detection_system::ErrorDetection;
use crate::utility::helper::{REMZAR_WALLET_LEN, canon_wallet_id_checked};
use crate::utility::logging_data::JsonLogger;

use colored::Colorize;
use dialoguer::Password;
use fips204::ml_dsa_65;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

/// Section 15: Debug Wallet Storage Keys.
pub struct S15DebugWalletStorageKeys;

impl S15DebugWalletStorageKeys {
    pub fn new() -> Self {
        Self
    }

    fn flush_stdout(json_logger: &JsonLogger, code: &str) -> Result<(), ErrorDetection> {
        io::stdout().flush().map_err(|e| {
            let msg = format!("Failed to flush stdout: {}", e);
            json_logger.log_error_event("debug", code, &msg).ok();
            ErrorDetection::IoError {
                message: msg,
                code: e.raw_os_error(),
                source: Some(Box::new(e)),
            }
        })
    }

    fn read_line_capped(
        prompt: &str,
        cap: usize,
        json_logger: &JsonLogger,
        log_code: &str,
    ) -> Result<String, ErrorDetection> {
        print!("{prompt}");
        Self::flush_stdout(json_logger, "DebugWalletFlushStdoutFailed")?;

        let mut s = String::new();
        io::stdin().read_line(&mut s).map_err(|e| {
            let msg = format!("Failed to read input: {}", e);
            json_logger.log_error_event("debug", log_code, &msg).ok();
            ErrorDetection::IoError {
                message: msg,
                code: e.raw_os_error(),
                source: Some(Box::new(e)),
            }
        })?;

        let trimmed = s.trim().to_string();

        if trimmed.len() > cap {
            let msg = format!("Input too long (max {} chars)", cap);
            json_logger
                .log_error_event("debug", "DebugWalletInputTooLong", &msg)
                .ok();
            return Err(ErrorDetection::ValidationError {
                message: msg,
                tx_id: None,
            });
        }

        Ok(trimmed)
    }

    fn read_yes_no(
        prompt: &str,
        cap: usize,
        json_logger: &JsonLogger,
        log_code: &str,
    ) -> Result<bool, ErrorDetection> {
        let s = Self::read_line_capped(prompt, cap, json_logger, log_code)?;
        match s.to_ascii_lowercase().as_str() {
            "yes" | "y" => Ok(true),
            "no" | "n" => Ok(false),
            _ => Err(ErrorDetection::ValidationError {
                message: "Please type yes or no.".into(),
                tx_id: None,
            }),
        }
    }

    fn read_wallet_address(
        prompt: &str,
        cap: usize,
        json_logger: &JsonLogger,
        log_code: &str,
    ) -> Result<String, ErrorDetection> {
        let raw = Self::read_line_capped(prompt, cap, json_logger, log_code)?;
        if raw.is_empty() {
            let msg = "Wallet address cannot be empty.".to_string();
            json_logger.log_error_event("debug", log_code, &msg).ok();
            return Err(ErrorDetection::ValidationError {
                message: msg,
                tx_id: None,
            });
        }

        canon_wallet_id_checked(&raw).map_err(|e| {
            let msg = format!("Invalid wallet address format: {}", e);
            json_logger.log_error_event("debug", log_code, &msg).ok();
            ErrorDetection::ValidationError {
                message: msg,
                tx_id: None,
            }
        })
    }

    fn read_existing_directory(
        prompt: &str,
        cap: usize,
        json_logger: &JsonLogger,
        log_code: &str,
    ) -> Result<PathBuf, ErrorDetection> {
        let raw = Self::read_line_capped(prompt, cap, json_logger, log_code)?;
        if raw.is_empty() {
            let msg = "The specified directory does not exist.".to_string();
            json_logger.log_error_event("debug", log_code, &msg).ok();
            return Err(ErrorDetection::ValidationError {
                message: msg,
                tx_id: None,
            });
        }

        let path = Path::new(&raw);
        if !path.exists() || !path.is_dir() {
            let msg = "The specified directory does not exist.".to_string();
            json_logger.log_error_event("debug", log_code, &msg).ok();
            return Err(ErrorDetection::ValidationError {
                message: msg,
                tx_id: None,
            });
        }

        path.canonicalize().map_err(|e| {
            let msg = format!("Failed to resolve wallet directory path: {}", e);
            json_logger.log_error_event("debug", log_code, &msg).ok();
            ErrorDetection::IoError {
                message: msg,
                code: e.raw_os_error(),
                source: Some(Box::new(e)),
            }
        })
    }

    // ─────────────────────────────────────────────────────────────────────
    // 15) Debug Wallet Storage Keys (CLI DB) — hardened
    // ─────────────────────────────────────────────────────────────────────
    pub fn debug_keys(&self, json_logger: &JsonLogger) -> Result<(), ErrorDetection> {
        println!("{}", "🔹 Debug Wallet Storage Keys".cyan());

        const MAX_YN_INPUT_LEN: usize = 16;
        const MAX_ADDR_INPUT_LEN: usize = REMZAR_WALLET_LEN + 8;
        const MAX_DIR_INPUT_LEN: usize = 4096;
        const MAX_ATTEMPTS: usize = 5;

        // ── Prompt to proceed (guarded) ───────────────────────────
        let mut attempts = 0usize;
        let proceed = loop {
            attempts = attempts.saturating_add(1);
            if attempts > MAX_ATTEMPTS {
                println!(
                    "{}",
                    "❌ Too many invalid attempts. Returning to the menu.".red()
                );
                return Ok(());
            }

            match Self::read_yes_no(
                &format!(
                    "{}",
                    "🛠️ Do you want to DEBUG your wallet? (yes/no): ".yellow()
                ),
                MAX_YN_INPUT_LEN,
                json_logger,
                "ConfirmDebugReadFailed",
            ) {
                Ok(v) => break v,
                Err(ErrorDetection::ValidationError { message, .. }) => {
                    println!("{}", format!("❌ {}", message).red());
                    continue;
                }
                Err(e) => return Err(e),
            }
        };

        if !proceed {
            println!("{}", "❌ Returning to the menu.".red());
            return Ok(());
        }

        // ── Wallet address prompt & validation ───────────────────
        let wallet_address = Self::read_wallet_address(
            "🔑 Enter your Wallet Address: ",
            MAX_ADDR_INPUT_LEN,
            json_logger,
            "WalletAddrInvalid",
        )?;

        println!("✅ Wallet Address Validation: {}", "[PASSED]".green());
        println!("📌 Address: {}", wallet_address.blue());

        // ── Passphrase prompt (zeroize) ───────────────────────────
        let mut passphrase = Password::new()
            .with_prompt("🔒 Enter your Passphrase")
            .allow_empty_password(false)
            .interact()
            .map_err(|e| {
                let msg = format!("Failed to read passphrase: {}", e);
                json_logger
                    .log_error_event("debug", "ReadPassphraseFailed", &msg)
                    .ok();
                ErrorDetection::IoError {
                    message: msg,
                    code: None,
                    source: Some(Box::new(e)),
                }
            })?;

        // ── Wallet directory prompt & validation ────────────────
        let wallet_dir = match Self::read_existing_directory(
            "📂 Enter the directory where your wallet file is stored: ",
            MAX_DIR_INPUT_LEN,
            json_logger,
            "WalletDirInvalid",
        ) {
            Ok(v) => v,
            Err(e) => {
                passphrase.zeroize();
                return Err(e);
            }
        };

        // ── Read & decrypt wallet file (zeroize secrets) ─────────
        let wallet_file = wallet_dir.join(format!("{}.wallet", wallet_address));
        if !wallet_file.exists() || !wallet_file.is_file() {
            passphrase.zeroize();
            let msg = format!("Wallet file not found at: {}", wallet_file.display());
            json_logger
                .log_error_event("debug", "WalletFileMissing", &msg)
                .ok();
            return Err(ErrorDetection::NotFound { resource: msg });
        }

        let mut encrypted_sk_bytes = fs::read(&wallet_file).map_err(|e| {
            passphrase.zeroize();
            let msg = format!(
                "Failed to read wallet file '{}': {}",
                wallet_file.display(),
                e
            );
            json_logger
                .log_error_event("debug", "ReadWalletFileFailed", &msg)
                .ok();
            ErrorDetection::IoError {
                message: msg,
                code: e.raw_os_error(),
                source: Some(Box::new(e)),
            }
        })?;

        let mut decrypted_sk = Cryption::decrypt_private_key_bytes(
            &encrypted_sk_bytes,
            &passphrase,
        )
        .map_err(|_| {
            passphrase.zeroize();
            let msg =
                "Failed to decrypt the private key. Ensure the passphrase is correct.".to_string();
            json_logger
                .log_error_event("debug", "DecryptSKFailed", &msg)
                .ok();
            ErrorDetection::DecryptionError { message: msg }
        })?;

        if decrypted_sk.len() != ml_dsa_65::SK_LEN {
            passphrase.zeroize();
            decrypted_sk.zeroize();
            encrypted_sk_bytes.zeroize();

            let msg = format!(
                "Decrypted secret key length mismatch: expected {} bytes, got {}",
                ml_dsa_65::SK_LEN,
                decrypted_sk.len()
            );
            json_logger
                .log_error_event("debug", "SecretLengthMismatch", &msg)
                .ok();

            return Err(ErrorDetection::ValidationError {
                message: msg,
                tx_id: None,
            });
        }

        passphrase.zeroize();
        decrypted_sk.zeroize();
        encrypted_sk_bytes.zeroize();

        println!("✅ Private Key Validation: {}", "[PASSED]".green());

        // ── File metadata output ─────────────────────────────────
        println!("\n{}", "📂 Encrypted Wallet Details".cyan().bold());
        let metadata = fs::metadata(&wallet_file).map_err(|e| {
            let msg = format!(
                "Failed to get metadata for wallet file '{}': {}",
                wallet_file.display(),
                e
            );
            json_logger
                .log_error_event("debug", "MetadataFailed", &msg)
                .ok();
            ErrorDetection::IoError {
                message: msg,
                code: e.raw_os_error(),
                source: Some(Box::new(e)),
            }
        })?;

        println!("📄 File Path: {}", wallet_file.display().to_string().blue());
        println!("📏 File Size: {} bytes", metadata.len().to_string().green());

        if let Ok(created) = metadata.created() {
            println!(
                "📅 Created: {}",
                chrono::DateTime::<chrono::Utc>::from(created)
                    .to_rfc3339()
                    .green()
            );
        }

        if let Ok(modified) = metadata.modified() {
            println!(
                "🕒 Last Modified: {}",
                chrono::DateTime::<chrono::Utc>::from(modified)
                    .to_rfc3339()
                    .green()
            );
        }

        // ── Wallet hash/key information ──────────────────────────
        println!(
            "\n{}",
            "🔑 Wallet Hashing and Key Information".cyan().bold()
        );

        let prefix = wallet_address.chars().next().unwrap_or('\0');
        let core_hash = wallet_address
            .strip_prefix(prefix)
            .unwrap_or(wallet_address.as_str());

        println!(
            "🔹 Prefix: {}  {}",
            prefix.to_string().blue(),
            if prefix == 'r' {
                "[VALID]".green()
            } else {
                "[INVALID]".red()
            }
        );
        println!("🔹 Core Hash (512-bit): {}", core_hash);
        println!("🔹 Hashing System Used: {}", "BLAKE3-XOF(64)".green());

        println!("\n{}", "🔎 Wallet Key Specifications".cyan().bold());

        println!(
            "➡️ ML-DSA-65 Private Key (raw): {}",
            format!("{} bytes", ml_dsa_65::SK_LEN).magenta()
        );
        println!(
            "➡️ ML-DSA-65 Private Key (hex encoded): {}",
            format!("{} characters", ml_dsa_65::SK_LEN * 2).magenta()
        );
        println!(
            "➡️ ML-DSA-65 Public Key (raw): {}",
            format!("{} bytes", ml_dsa_65::PK_LEN).magenta()
        );
        println!(
            "➡️ ML-DSA-65 Public Key (hex encoded): {}",
            format!("{} characters", ml_dsa_65::PK_LEN * 2).magenta()
        );
        println!(
            "➡️ ML-DSA-65 Signature (raw): {}",
            format!("{} bytes", ml_dsa_65::SIG_LEN).magenta()
        );
        println!(
            "➡️ ML-DSA-65 Signature (hex encoded): {}",
            format!("{} characters", ml_dsa_65::SIG_LEN * 2).magenta()
        );

        println!(
            "➡️ Wallet Address Core Hash (raw): {}",
            "64 bytes".magenta()
        );
        println!(
            "➡️ Wallet Address Core Hash (hex encoded): {}",
            "128 characters".magenta()
        );
        println!(
            "➡️ Final Wallet Address (with 'r' prefix): {}",
            "129 characters".magenta()
        );

        println!("\n{}", "Proof and Clarification:".cyan());
        println!(
            "ML-DSA-65 private key is {} bytes ({} hex chars).",
            ml_dsa_65::SK_LEN,
            ml_dsa_65::SK_LEN * 2
        );
        println!(
            "ML-DSA-65 public key is {} bytes ({} hex chars).",
            ml_dsa_65::PK_LEN,
            ml_dsa_65::PK_LEN * 2
        );
        println!(
            "ML-DSA-65 signature is {} bytes ({} hex chars).",
            ml_dsa_65::SIG_LEN,
            ml_dsa_65::SIG_LEN * 2
        );
        println!(
            "Wallet address: BLAKE3-XOF(64)(pubkey) → 64 bytes (128 hex chars) + 'r' prefix → 129 chars total."
        );

        println!("{}", "✅ Debugging Completed Successfully.".green());

        Ok(())
    }
}

impl Default for S15DebugWalletStorageKeys {
    fn default() -> Self {
        Self::new()
    }
}
