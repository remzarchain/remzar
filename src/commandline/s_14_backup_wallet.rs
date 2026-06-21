//! src/commandline/s_14_backup_wallet.rs

use crate::cryptography::ml_dsa_65_005_encryption::Cryption;
use crate::cryptography::ml_dsa_65_006_edwallet::MLDSA65Wallet;
use crate::runtime::p2p_006_sync_runtime::NodeOpts;
use crate::storage::rocksdb_000_directory::DirectoryDB;
use crate::utility::alpha_002_error_detection_system::ErrorDetection;
use crate::utility::helper::{REMZAR_WALLET_LEN, canon_wallet_id_checked};
use crate::utility::logging_data::JsonLogger;

use colored::Colorize;
use dialoguer::Password;
use fips204::ml_dsa_65;
use std::fs;
use std::io::{self, ErrorKind, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

/// Section 14: Backup Wallet.
pub struct S14BackupWallet;

impl S14BackupWallet {
    pub fn new() -> Self {
        Self
    }

    fn flush_stdout(json_logger: &JsonLogger, code: &str) -> Result<(), ErrorDetection> {
        io::stdout().flush().map_err(|e| {
            let msg = format!("Failed to flush stdout: {e}");
            json_logger.log_error_event("wallet", code, &msg).ok();
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
        Self::flush_stdout(json_logger, "BackupWalletFlushStdoutFailed")?;

        let mut s = String::new();
        io::stdin().read_line(&mut s).map_err(|e| {
            let msg = format!("Failed to read input: {e}");
            json_logger.log_error_event("wallet", log_code, &msg).ok();
            ErrorDetection::IoError {
                message: msg,
                code: e.raw_os_error(),
                source: Some(Box::new(e)),
            }
        })?;

        let visible = s.trim_end_matches(&['\r', '\n'][..]);

        if visible.len() > cap {
            let msg = format!("Input too long (max {} chars).", cap);
            json_logger
                .log_error_event("wallet", "BackupWalletInputTooLong", &msg)
                .ok();
            return Err(ErrorDetection::ValidationError {
                message: msg,
                tx_id: None,
            });
        }

        Ok(visible.trim().to_string())
    }

    fn read_yes_no(
        prompt: &str,
        cap: usize,
        json_logger: &JsonLogger,
        log_code: &str,
    ) -> Result<bool, ErrorDetection> {
        let s = Self::read_line_capped(prompt, cap, json_logger, log_code)?;
        match s.trim().to_ascii_lowercase().as_str() {
            "yes" | "y" => Ok(true),
            "no" | "n" => Ok(false),
            _ => Err(ErrorDetection::ValidationError {
                message: "Please type yes or no.".into(),
                tx_id: None,
            }),
        }
    }

    fn read_wallet_or_exit(
        prompt: &str,
        cap: usize,
        json_logger: &JsonLogger,
        log_code: &str,
    ) -> Result<Option<String>, ErrorDetection> {
        let raw = Self::read_line_capped(prompt, cap, json_logger, log_code)?;
        if raw.eq_ignore_ascii_case("exit") {
            return Ok(None);
        }

        if raw.is_empty() {
            return Err(ErrorDetection::ValidationError {
                message: "Wallet address cannot be empty.".into(),
                tx_id: None,
            });
        }

        let canon = canon_wallet_id_checked(&raw).map_err(|e| {
            let msg = format!("Invalid wallet address: {}", e);
            json_logger.log_error_event("wallet", log_code, &msg).ok();
            ErrorDetection::ValidationError {
                message: msg,
                tx_id: None,
            }
        })?;

        Ok(Some(canon))
    }

    fn validate_wallet_file(
        wallet_file: &Path,
        max_wallet_file_bytes: u64,
        json_logger: &JsonLogger,
    ) -> Result<(), ErrorDetection> {
        let meta = fs::metadata(wallet_file).map_err(|e| {
            let msg = format!(
                "Failed to stat wallet file '{}': {}",
                wallet_file.display(),
                e
            );
            json_logger
                .log_error_event("wallet", "BackupWalletStatFailed", &msg)
                .ok();
            ErrorDetection::IoError {
                message: msg,
                code: e.raw_os_error(),
                source: Some(Box::new(e)),
            }
        })?;

        if !meta.is_file() {
            let msg = format!(
                "Wallet path is not a regular file: {}",
                wallet_file.display()
            );
            json_logger
                .log_error_event("wallet", "BackupWalletNotRegularFile", &msg)
                .ok();
            return Err(ErrorDetection::ValidationError {
                message: msg,
                tx_id: None,
            });
        }

        if meta.len() == 0 {
            let msg = format!("Wallet file is empty/corrupt: {}", wallet_file.display());
            json_logger
                .log_error_event("wallet", "BackupWalletEmptyFile", &msg)
                .ok();
            return Err(ErrorDetection::ValidationError {
                message: msg,
                tx_id: None,
            });
        }

        if meta.len() > max_wallet_file_bytes {
            let msg = format!(
                "Wallet file too large: {} bytes exceeds safety max {}",
                meta.len(),
                max_wallet_file_bytes
            );
            json_logger
                .log_error_event("wallet", "BackupWalletFileTooLarge", &msg)
                .ok();
            return Err(ErrorDetection::ValidationError {
                message: msg,
                tx_id: None,
            });
        }

        Ok(())
    }

    fn verify_wallet_decrypt_matches_address(
        wallet_file: &Path,
        passphrase: &str,
        expected_wallet: &str,
        json_logger: &JsonLogger,
    ) -> Result<(), ErrorDetection> {
        let mut encrypted_sk = fs::read(wallet_file).map_err(|e| {
            let msg = format!(
                "Failed to read wallet file '{}': {}",
                wallet_file.display(),
                e
            );
            json_logger
                .log_error_event("wallet", "ReadWalletFileFailed", &msg)
                .ok();
            ErrorDetection::IoError {
                message: msg,
                code: e.raw_os_error(),
                source: Some(Box::new(e)),
            }
        })?;

        let mut plaintext = Cryption::decrypt_private_key_bytes(&encrypted_sk, passphrase)
            .map_err(|e| {
                encrypted_sk.zeroize();

                let msg = format!("Failed to decrypt wallet file: {e}");
                json_logger
                    .log_error_event("wallet", "WalletDecryptionFailed", &msg)
                    .ok();
                ErrorDetection::DecryptionError { message: msg }
            })?;

        encrypted_sk.zeroize();

        let mut secret_bytes: Vec<u8> = if plaintext.len() == ml_dsa_65::SK_LEN {
            let out = plaintext.clone();
            plaintext.zeroize();
            out
        } else {
            let mut secret_hex = match std::str::from_utf8(&plaintext) {
                Ok(s) => s.trim().to_ascii_lowercase(),
                Err(_) => {
                    plaintext.zeroize();

                    let msg = format!(
                        "Decrypted secret is not {} raw bytes and is not valid UTF-8; wallet format unknown/corrupt",
                        ml_dsa_65::SK_LEN
                    );
                    json_logger
                        .log_error_event("wallet", "WalletSecretUtf8Invalid", &msg)
                        .ok();
                    return Err(ErrorDetection::ValidationError {
                        message: msg,
                        tx_id: None,
                    });
                }
            };

            plaintext.zeroize();

            if secret_hex.len() != ml_dsa_65::SK_LEN * 2
                || !secret_hex.chars().all(|c| c.is_ascii_hexdigit())
            {
                let got = secret_hex.len();
                secret_hex.zeroize();

                let msg = format!(
                    "Decrypted secret has unexpected length/format: expected {} hex chars, got {}",
                    ml_dsa_65::SK_LEN * 2,
                    got
                );
                json_logger
                    .log_error_event("wallet", "WalletSecretFormatMismatch", &msg)
                    .ok();
                return Err(ErrorDetection::ValidationError {
                    message: msg,
                    tx_id: None,
                });
            }

            let decoded = hex::decode(&secret_hex).map_err(|e| {
                let msg = format!("Failed to decode decrypted secret hex: {e:?}");
                json_logger
                    .log_error_event("wallet", "WalletSecretHexDecodeFailed", &msg)
                    .ok();
                ErrorDetection::ValidationError {
                    message: msg,
                    tx_id: None,
                }
            })?;

            secret_hex.zeroize();
            decoded
        };

        if secret_bytes.len() != ml_dsa_65::SK_LEN {
            let got = secret_bytes.len();
            secret_bytes.zeroize();

            let msg = format!(
                "Decrypted secret length mismatch: expected {} bytes, got {}",
                ml_dsa_65::SK_LEN,
                got
            );
            json_logger
                .log_error_event("wallet", "WalletSecretLengthMismatch", &msg)
                .ok();

            return Err(ErrorDetection::ValidationError {
                message: msg,
                tx_id: None,
            });
        }

        let recovered_addr =
            MLDSA65Wallet::address_from_secret_bytes(&secret_bytes).map_err(|e| {
                secret_bytes.zeroize();

                let msg = format!("Unable to derive wallet address from secret: {e}");
                json_logger
                    .log_error_event("wallet", "WalletSecretAddressRecoverFailed", &msg)
                    .ok();

                ErrorDetection::ValidationError {
                    message: msg,
                    tx_id: None,
                }
            })?;

        secret_bytes.zeroize();

        if recovered_addr != expected_wallet {
            let msg = format!(
                "Decrypted secret does not match the requested wallet address. expected={} recovered={}",
                expected_wallet, recovered_addr
            );
            json_logger
                .log_error_event("wallet", "WalletSecretAddressMismatch", &msg)
                .ok();

            return Err(ErrorDetection::ValidationError {
                message: msg,
                tx_id: None,
            });
        }

        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────────
    // 14) Backup Wallet (CLI DB) — hardened
    // ─────────────────────────────────────────────────────────────────────
    pub fn debug_backup_wallet(
        &self,
        opts: &NodeOpts,
        json_logger: &JsonLogger,
    ) -> Result<(), ErrorDetection> {
        println!("{}", "🔹 Wallet Backup".cyan());

        const MAX_YN_INPUT_LEN: usize = 16;
        const MAX_ADDR_INPUT_LEN: usize = REMZAR_WALLET_LEN;
        const MAX_DIR_INPUT_LEN: usize = 4096;
        const MAX_ATTEMPTS: usize = 10;
        const MAX_PASSPHRASE_BYTES: usize = 256;
        const MAX_WALLET_FILE_BYTES: u64 = 512 * 1024;

        // Prompt to proceed
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
                "💾 Do you want to back up your keys? (yes/no): ",
                MAX_YN_INPUT_LEN,
                json_logger,
                "BackupPromptReadFailed",
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

        // Wallet address prompt
        let wallet_address = {
            let mut tries = 0usize;
            loop {
                tries = tries.saturating_add(1);
                if tries > MAX_ATTEMPTS {
                    let msg = "Too many invalid wallet address attempts. Returning to the menu."
                        .to_string();
                    println!("{}", format!("❌ {}", msg).red());
                    json_logger
                        .log_error_event("wallet", "BackupAddrTooManyAttempts", &msg)
                        .ok();
                    return Ok(());
                }

                match Self::read_wallet_or_exit(
                    "🔑 Enter your Wallet Address (or type \"exit\" to return to menu): ",
                    MAX_ADDR_INPUT_LEN,
                    json_logger,
                    "BackupWalletAddrReadFailed",
                ) {
                    Ok(Some(canon)) => break canon,
                    Ok(None) => {
                        println!("{}", "❌ Returning to the menu.".red());
                        return Ok(());
                    }
                    Err(ErrorDetection::ValidationError { message, .. }) => {
                        println!("{}", format!("❌ {}", message).red());
                        println!(
                            "{}",
                            "❌ Expected: 'r' + 128 lowercase hex characters (129 total).".red()
                        );
                        continue;
                    }
                    Err(e) => return Err(e),
                }
            }
        };

        // Passphrase prompt
        let mut passphrase = {
            let mut tries = 0usize;
            loop {
                tries = tries.saturating_add(1);
                if tries > MAX_ATTEMPTS {
                    let msg =
                        "Too many invalid passphrase attempts. Returning to the menu.".to_string();
                    println!("{}", format!("❌ {}", msg).red());
                    json_logger
                        .log_error_event("wallet", "BackupPassTooManyAttempts", &msg)
                        .ok();
                    return Ok(());
                }

                let mut input = Password::new()
                    .with_prompt("🔒 Enter passphrase for wallet decryption")
                    .allow_empty_password(false)
                    .interact()
                    .map_err(|e| ErrorDetection::IoError {
                        message: format!("Failed to read passphrase: {e}"),
                        code: None,
                        source: Some(Box::new(e)),
                    })?;

                let mut confirm = Password::new()
                    .with_prompt("🔒 Confirm your passphrase")
                    .allow_empty_password(false)
                    .interact()
                    .map_err(|e| ErrorDetection::IoError {
                        message: format!("Failed to read passphrase confirmation: {e}"),
                        code: None,
                        source: Some(Box::new(e)),
                    })?;

                if input.is_empty() {
                    input.zeroize();
                    confirm.zeroize();
                    println!("{}", "❌ Passphrase cannot be empty. Retry.".red());
                    continue;
                }

                if input.len() > MAX_PASSPHRASE_BYTES || confirm.len() > MAX_PASSPHRASE_BYTES {
                    input.zeroize();
                    confirm.zeroize();
                    println!(
                        "{}",
                        format!(
                            "❌ Passphrase too long (max {} characters). Retry.",
                            MAX_PASSPHRASE_BYTES
                        )
                        .red()
                    );
                    continue;
                }

                if input != confirm {
                    input.zeroize();
                    confirm.zeroize();
                    println!("{}", "❌ Passphrases do not match. Retry.".red());
                    continue;
                }

                confirm.zeroize();
                break input;
            }
        };

        // Always use official Remzar wallets directory for source
        let directory = DirectoryDB::from_node_opts(opts).map_err(|e| {
            let msg = format!("Failed to initialize directories: {}", e);
            json_logger
                .log_error_event("wallet", "InitDirectoriesFailed", &msg)
                .ok();
            ErrorDetection::IoError {
                message: msg,
                code: None,
                source: None,
            }
        })?;

        let wallet_file = directory
            .wallets_path
            .join(format!("{}.wallet", wallet_address));

        if !wallet_file.exists() {
            passphrase.zeroize();
            let msg = format!("Wallet file not found at: {}", wallet_file.display());
            json_logger
                .log_error_event("wallet", "WalletFileNotFound", &msg)
                .ok();
            return Err(ErrorDetection::NotFound { resource: msg });
        }

        Self::validate_wallet_file(&wallet_file, MAX_WALLET_FILE_BYTES, json_logger)?;

        // Read & decrypt to verify passphrase and address binding, then wipe passphrase
        let verify_result = Self::verify_wallet_decrypt_matches_address(
            &wallet_file,
            &passphrase,
            &wallet_address,
            json_logger,
        );
        passphrase.zeroize();
        verify_result?;

        // Default backup path: ~/remzar-wallet-backups/<wallet_address>/
        let home_backup_root = directories::BaseDirs::new()
            .map(|dirs| {
                dirs.home_dir()
                    .join("remzar-wallet-backups")
                    .join(&wallet_address)
            })
            .unwrap_or_else(|| {
                PathBuf::from(format!("./remzar-wallet-backups/{}", wallet_address))
            });

        println!(
            "{}",
            format!(
                "📂 Hit Enter to use default [{}], or enter a different backup directory:",
                home_backup_root.display()
            )
            .yellow()
        );

        let backup_dir =
            Self::read_line_capped("", MAX_DIR_INPUT_LEN, json_logger, "BackupDirReadFailed")?;

        let backup_path = if backup_dir.trim().is_empty() {
            home_backup_root
        } else {
            PathBuf::from(backup_dir.trim())
        };

        if !backup_path.exists() {
            fs::create_dir_all(&backup_path).map_err(|e| {
                let msg = format!("Failed to create backup directory: {e}");
                json_logger
                    .log_error_event("wallet", "CreateBackupDirFailed", &msg)
                    .ok();
                ErrorDetection::IoError {
                    message: msg,
                    code: e.raw_os_error(),
                    source: Some(Box::new(e)),
                }
            })?;
        } else if !backup_path.is_dir() {
            let msg = format!("Backup path is not a directory: {}", backup_path.display());
            json_logger
                .log_error_event("wallet", "BackupPathNotDir", &msg)
                .ok();
            return Err(ErrorDetection::ValidationError {
                message: msg,
                tx_id: None,
            });
        }

        // Refuse obvious bad target: same source dir
        if backup_path == directory.wallets_path {
            let msg = "Refusing to back up into the live wallets directory.".to_string();
            json_logger
                .log_error_event("wallet", "BackupIntoLiveWalletDirRefused", &msg)
                .ok();
            return Err(ErrorDetection::ValidationError {
                message: msg,
                tx_id: None,
            });
        }

        // Atomic-ish copy: copy -> rename; refuse overwrite
        let backup_file = backup_path.join(format!("{}.wallet", wallet_address));
        if backup_file.exists() {
            let msg = format!(
                "Refusing to overwrite existing backup file: {}",
                backup_file.display()
            );
            json_logger
                .log_error_event("wallet", "BackupFileAlreadyExists", &msg)
                .ok();
            return Err(ErrorDetection::ValidationError {
                message: msg,
                tx_id: None,
            });
        }

        let tmp_backup = backup_path.join(format!("{}.wallet.tmp", wallet_address));

        if let Err(e) = fs::remove_file(&tmp_backup)
            && e.kind() != ErrorKind::NotFound
        {
            json_logger
                .log_error_event(
                    "wallet",
                    "RemoveTmpBackupFailed",
                    &format!("Failed to remove temp backup file: {e}"),
                )
                .ok();
        }

        fs::copy(&wallet_file, &tmp_backup).map_err(|e| {
            let msg = format!("Failed to back up wallet (tmp copy): {e}");
            json_logger
                .log_error_event("wallet", "CopyBackupTmpFailed", &msg)
                .ok();
            ErrorDetection::IoError {
                message: msg,
                code: e.raw_os_error(),
                source: Some(Box::new(e)),
            }
        })?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Err(e) = fs::set_permissions(&tmp_backup, fs::Permissions::from_mode(0o600)) {
                json_logger
                    .log_error_event(
                        "wallet",
                        "BackupTmpPermissionsHardeningFailed",
                        &format!("set_permissions(0600) failed: {}", e),
                    )
                    .ok();
            }
        }

        if let Err(e) = fs::rename(&tmp_backup, &backup_file) {
            if let Err(remove_err) = fs::remove_file(&tmp_backup)
                && remove_err.kind() != ErrorKind::NotFound
            {
                json_logger
                    .log_error_event(
                        "wallet",
                        "CleanupTmpBackupAfterRenameFailureFailed",
                        &format!(
                            "Failed to remove temp backup after rename failure: {}",
                            remove_err
                        ),
                    )
                    .ok();
            }

            let msg = format!(
                "Failed to finalize backup file (rename {} -> {}): {}",
                tmp_backup.display(),
                backup_file.display(),
                e
            );
            json_logger
                .log_error_event("wallet", "FinalizeBackupRenameFailed", &msg)
                .ok();
            return Err(ErrorDetection::IoError {
                message: msg,
                code: e.raw_os_error(),
                source: Some(Box::new(e)),
            });
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Err(e) = fs::set_permissions(&backup_file, fs::Permissions::from_mode(0o600)) {
                json_logger
                    .log_error_event(
                        "wallet",
                        "BackupFinalPermissionsHardeningFailed",
                        &format!("set_permissions(0600) failed: {}", e),
                    )
                    .ok();
            }
        }

        println!(
            "{}",
            format!(
                "✅ Wallet successfully backed up at: {}",
                backup_file.display()
            )
            .green()
        );

        Ok(())
    }
}

impl Default for S14BackupWallet {
    fn default() -> Self {
        Self::new()
    }
}
