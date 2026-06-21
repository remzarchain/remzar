//! src/commandline/s_13_wallet_utilities.rs

use crate::cryptography::ml_dsa_65_005_encryption::Cryption;
use crate::cryptography::ml_dsa_65_006_edwallet::MLDSA65Wallet;
use crate::utility::alpha_001_global_configuration::GlobalConfiguration;
use crate::utility::alpha_002_error_detection_system::ErrorDetection;
use crate::utility::helper::{REMZAR_WALLET_LEN, canon_wallet_id_checked};
use crate::utility::logging_data::JsonLogger;

use colored::Colorize;
use dialoguer::Password;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;
use uuid::Uuid;
use zeroize::Zeroize;

/// Section 13: Wallet utilities.
pub struct S13WalletUtilities;

impl S13WalletUtilities {
    pub fn new() -> Self {
        Self
    }

    fn flush_stdout(json_logger: &JsonLogger, code: &str) -> Result<(), ErrorDetection> {
        io::stdout().flush().map_err(|e| {
            let msg = format!("Failed to flush stdout: {}", e);
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
        Self::flush_stdout(json_logger, "WalletUtilsFlushStdoutFailed")?;

        let mut s = String::new();
        io::stdin().read_line(&mut s).map_err(|e| {
            let msg = format!("Failed to read input: {}", e);
            json_logger.log_error_event("wallet", log_code, &msg).ok();
            ErrorDetection::IoError {
                message: msg,
                code: e.raw_os_error(),
                source: Some(Box::new(e)),
            }
        })?;

        let visible = s.trim_end_matches(&['\r', '\n'][..]);

        if visible.len() > cap {
            let msg = format!("Input too long (max {} chars)", cap);
            json_logger
                .log_error_event("wallet", "WalletUtilsInputTooLong", &msg)
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

    fn read_existing_directory(
        prompt: &str,
        cap: usize,
        json_logger: &JsonLogger,
        log_code: &str,
    ) -> Result<PathBuf, ErrorDetection> {
        let raw = Self::read_line_capped(prompt, cap, json_logger, log_code)?;
        if raw.is_empty() {
            return Err(ErrorDetection::ValidationError {
                message: "Directory path is empty.".into(),
                tx_id: None,
            });
        }

        let path = PathBuf::from(raw);
        if !path.exists() || !path.is_dir() {
            let msg = "Directory does not exist or is not a directory.".to_string();
            json_logger.log_error_event("wallet", log_code, &msg).ok();
            return Err(ErrorDetection::ValidationError {
                message: msg,
                tx_id: None,
            });
        }

        Ok(path)
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
                .log_error_event("wallet", "WalletUtilsStatWalletFileFailed", &msg)
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
                .log_error_event("wallet", "WalletUtilsWalletFileNotRegular", &msg)
                .ok();
            return Err(ErrorDetection::ValidationError {
                message: msg,
                tx_id: None,
            });
        }

        if meta.len() == 0 {
            let msg = format!("Wallet file is empty/corrupt: {}", wallet_file.display());
            json_logger
                .log_error_event("wallet", "WalletUtilsWalletFileEmpty", &msg)
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
                .log_error_event("wallet", "WalletUtilsWalletFileTooLarge", &msg)
                .ok();
            return Err(ErrorDetection::ValidationError {
                message: msg,
                tx_id: None,
            });
        }

        Ok(())
    }

    fn decrypt_wallet_secret_to_hex(
        wallet_file: &Path,
        passphrase: &str,
        json_logger: &JsonLogger,
    ) -> Result<String, ErrorDetection> {
        use fips204::ml_dsa_65;

        let mut encrypted_pk = fs::read(wallet_file).map_err(|e| {
            let msg = format!(
                "Failed to read wallet file '{}': {}",
                wallet_file.display(),
                e
            );
            json_logger
                .log_error_event("wallet", "WalletUtilsReadWalletFileFailed", &msg)
                .ok();
            ErrorDetection::IoError {
                message: msg,
                code: e.raw_os_error(),
                source: Some(Box::new(e)),
            }
        })?;

        let mut plaintext = Cryption::decrypt_private_key_bytes(&encrypted_pk, passphrase)
            .map_err(|e| {
                encrypted_pk.zeroize();

                let msg = format!("Failed to decrypt private key: {e}");
                json_logger
                    .log_error_event("wallet", "WalletUtilsDecryptFailed", &msg)
                    .ok();
                ErrorDetection::DecryptionError { message: msg }
            })?;

        encrypted_pk.zeroize();

        // Preferred PQ wallet path: raw ML-DSA-65 secret bytes.
        if plaintext.len() == ml_dsa_65::SK_LEN {
            let secret_hex = hex::encode(&plaintext);
            plaintext.zeroize();
            return Ok(secret_hex);
        }

        // Legacy compatibility path: decrypted plaintext is a UTF-8 hex string.
        let mut secret_hex = match std::str::from_utf8(&plaintext) {
            Ok(s) => s.trim().to_ascii_lowercase(),
            Err(_) => {
                plaintext.zeroize();

                let msg = format!(
                    "Decrypted secret is not {} raw bytes and is not valid UTF-8; wallet format unknown/corrupt",
                    ml_dsa_65::SK_LEN
                );
                json_logger
                    .log_error_event("wallet", "WalletUtilsSecretUtf8Invalid", &msg)
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
                .log_error_event("wallet", "WalletUtilsSecretFormatMismatch", &msg)
                .ok();
            return Err(ErrorDetection::ValidationError {
                message: msg,
                tx_id: None,
            });
        }

        Ok(secret_hex)
    }

    // ─────────────────────────────────────────────────────────────────────
    // 13) Wallet utilities – either view private key or recover address
    // ─────────────────────────────────────────────────────────────────────
    pub fn debug_open_encrypted_key(
        &mut self,
        json_logger: &JsonLogger,
    ) -> Result<(), ErrorDetection> {
        const MAX_MENU_INPUT_LEN: usize = 16;
        const MAX_YN_INPUT_LEN: usize = 16;
        const MAX_PATH_INPUT_LEN: usize = 4096;
        const MAX_ADDR_INPUT_LEN: usize = REMZAR_WALLET_LEN;
        const MAX_ATTEMPTS: usize = 10;
        const TEMP_LIFETIME_SECS: u64 = 30;
        const MAX_WALLET_FILE_BYTES: u64 = 512 * 1024;
        const MAX_PASSPHRASE_BYTES: usize = 256;

        json_logger
            .log_error_event("wallet", "WalletMenuOpened", "Wallet menu opened")
            .ok();

        println!("{}", "🔹 Wallet Utilities".cyan());
        println!("  1) View private key from an encrypted wallet file");
        println!("  2) Recover public address from a raw private key");
        println!("  3) Return to menu");

        let choice = match Self::read_line_capped(
            "Select option (1-3): ",
            MAX_MENU_INPUT_LEN,
            json_logger,
            "WalletMenuReadChoiceFailed",
        ) {
            Ok(v) => v,
            Err(e) => {
                println!("{}", format!("❌ {}", e).red());
                json_logger
                    .log_error_event("wallet", "WalletMenuInputTooLong", &e.to_string())
                    .ok();
                return Ok(());
            }
        };

        match choice.as_str() {
            "1" => {
                let mut attempts = 0usize;
                loop {
                    attempts = attempts.saturating_add(1);
                    if attempts > MAX_ATTEMPTS {
                        println!(
                            "{}",
                            "❌ Too many invalid attempts. Returning to menu.".red()
                        );
                        return Ok(());
                    }

                    match Self::read_yes_no(
                        "🔑 Do you want to check your private keys? (yes/no): ",
                        MAX_YN_INPUT_LEN,
                        json_logger,
                        "WalletUtilsReadConfirmationFailed",
                    ) {
                        Ok(true) => break,
                        Ok(false) => {
                            println!("{}", "❌ Returning to the menu.".red());
                            return Ok(());
                        }
                        Err(ErrorDetection::ValidationError { message, .. }) => {
                            println!("{}", format!("❌ {}", message).red());
                            continue;
                        }
                        Err(e) => return Err(e),
                    }
                }

                let wallet_address = {
                    let mut tries = 0usize;
                    loop {
                        tries = tries.saturating_add(1);
                        if tries > MAX_ATTEMPTS {
                            return Err(ErrorDetection::ValidationError {
                                message: "Too many invalid wallet address attempts.".into(),
                                tx_id: None,
                            });
                        }

                        match Self::read_wallet_or_exit(
                            "🔑 Enter Wallet Address (or type \"exit\" to return to menu): ",
                            MAX_ADDR_INPUT_LEN,
                            json_logger,
                            "WalletUtilsReadWalletAddressFailed",
                        ) {
                            Ok(Some(address)) => break address,
                            Ok(None) => {
                                println!("{}", "❌ Returning to the menu.".red());
                                return Ok(());
                            }
                            Err(ErrorDetection::ValidationError { message, .. }) => {
                                println!("{}", format!("❌ {}", message).red());
                                println!(
                                    "{}",
                                    "❌ Expected: 'r' + 128 lowercase hex characters (129 total)."
                                        .red()
                                );
                                continue;
                            }
                            Err(e) => return Err(e),
                        }
                    }
                };

                let mut passphrase = Password::new()
                    .with_prompt("🔒 Enter passphrase for wallet decryption")
                    .allow_empty_password(false)
                    .interact()
                    .map_err(|e| ErrorDetection::IoError {
                        message: e.to_string(),
                        code: None,
                        source: Some(Box::new(e)),
                    })?;

                if passphrase.len() > MAX_PASSPHRASE_BYTES {
                    passphrase.zeroize();
                    return Err(ErrorDetection::ValidationError {
                        message: format!(
                            "Passphrase too long (max {} characters).",
                            MAX_PASSPHRASE_BYTES
                        ),
                        tx_id: None,
                    });
                }

                let mut passphrase_confirm = Password::new()
                    .with_prompt("🔒 Confirm your passphrase")
                    .allow_empty_password(false)
                    .interact()
                    .map_err(|e| ErrorDetection::IoError {
                        message: e.to_string(),
                        code: None,
                        source: Some(Box::new(e)),
                    })?;

                if passphrase_confirm.len() > MAX_PASSPHRASE_BYTES {
                    passphrase.zeroize();
                    passphrase_confirm.zeroize();
                    return Err(ErrorDetection::ValidationError {
                        message: format!(
                            "Passphrase confirmation too long (max {} characters).",
                            MAX_PASSPHRASE_BYTES
                        ),
                        tx_id: None,
                    });
                }

                if passphrase != passphrase_confirm {
                    passphrase.zeroize();
                    passphrase_confirm.zeroize();

                    let msg = "Passphrase confirmation does not match.";
                    json_logger
                        .log_error_event("wallet", "WalletUtilsPassphraseMismatch", msg)
                        .ok();

                    return Err(ErrorDetection::ValidationError {
                        message: msg.into(),
                        tx_id: None,
                    });
                }
                passphrase_confirm.zeroize();

                let wallet_dir_path = Self::read_existing_directory(
                    "📂 Directory containing wallet file: ",
                    MAX_PATH_INPUT_LEN,
                    json_logger,
                    "WalletUtilsReadWalletDirectoryFailed",
                )?;

                let wallet_file = wallet_dir_path.join(format!("{}.wallet", wallet_address));
                if !wallet_file.exists() {
                    passphrase.zeroize();
                    let msg = format!("Wallet file not found: {}", wallet_file.display());
                    json_logger
                        .log_error_event("wallet", "WalletUtilsWalletFileMissing", &msg)
                        .ok();
                    return Err(ErrorDetection::NotFound { resource: msg });
                }

                Self::validate_wallet_file(&wallet_file, MAX_WALLET_FILE_BYTES, json_logger)?;

                let mut decrypted_pk =
                    Self::decrypt_wallet_secret_to_hex(&wallet_file, &passphrase, json_logger)
                        .inspect_err(|_e| {
                            passphrase.zeroize();
                        })?;

                passphrase.zeroize();

                // Guardrail: verify the decrypted private key actually corresponds
                // to the wallet address the user entered.
                let mut sk_bytes = hex::decode(&decrypted_pk).map_err(|e| {
                    decrypted_pk.zeroize();

                    let msg = format!("Failed to decode decrypted secret hex: {e}");
                    json_logger
                        .log_error_event("wallet", "WalletUtilsDecodeSecretHexFailed", &msg)
                        .ok();
                    ErrorDetection::ValidationError {
                        message: msg,
                        tx_id: None,
                    }
                })?;

                let recovered_addr =
                    MLDSA65Wallet::address_from_secret_bytes(&sk_bytes).map_err(|e| {
                        sk_bytes.zeroize();
                        decrypted_pk.zeroize();

                        let msg =
                            format!("Unable to derive address from decrypted private key: {e}");
                        json_logger
                            .log_error_event("wallet", "WalletUtilsRecoverAddressFailed", &msg)
                            .ok();
                        ErrorDetection::ValidationError {
                            message: msg,
                            tx_id: None,
                        }
                    })?;

                if recovered_addr != wallet_address {
                    sk_bytes.zeroize();
                    decrypted_pk.zeroize();

                    let msg = format!(
                        "Decrypted private key does not match the requested wallet address. expected={} recovered={}",
                        wallet_address, recovered_addr
                    );
                    json_logger
                        .log_error_event("wallet", "WalletUtilsAddressMismatch", &msg)
                        .ok();

                    return Err(ErrorDetection::ValidationError {
                        message: msg,
                        tx_id: None,
                    });
                }

                sk_bytes.zeroize();

                let tmp_dir_path = Self::read_existing_directory(
                    "📂 Temp directory to store decrypted key: ",
                    MAX_PATH_INPUT_LEN,
                    json_logger,
                    "WalletUtilsReadTempDirectoryFailed",
                )?;

                let tmp_path: PathBuf =
                    tmp_dir_path.join(format!("decrypted_{}.txt", Uuid::new_v4()));

                let mut f = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&tmp_path)
                    .map_err(|e| {
                        decrypted_pk.zeroize();

                        let msg = format!("Failed to create temp key file: {}", e);
                        json_logger
                            .log_error_event("wallet", "WalletUtilsCreateTempFileFailed", &msg)
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
                    if let Err(e) =
                        fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600))
                    {
                        json_logger
                            .log_error_event(
                                "wallet",
                                "TempKeyPermissionsHardeningFailed",
                                &format!("set_permissions(0600) failed: {}", e),
                            )
                            .ok();
                    }
                }

                f.write_all(decrypted_pk.as_bytes()).map_err(|e| {
                    decrypted_pk.zeroize();

                    let msg = format!("Failed to write temp key file: {}", e);
                    json_logger
                        .log_error_event("wallet", "WalletUtilsWriteTempFileFailed", &msg)
                        .ok();

                    ErrorDetection::IoError {
                        message: msg,
                        code: e.raw_os_error(),
                        source: Some(Box::new(e)),
                    }
                })?;

                f.flush().map_err(|e| {
                    decrypted_pk.zeroize();

                    let msg = format!("Failed to flush temp key file: {}", e);
                    json_logger
                        .log_error_event("wallet", "WalletUtilsFlushTempFileFailed", &msg)
                        .ok();

                    ErrorDetection::IoError {
                        message: msg,
                        code: e.raw_os_error(),
                        source: Some(Box::new(e)),
                    }
                })?;

                decrypted_pk.zeroize();

                println!(
                    "{}",
                    format!("✅ Private key saved at: {}", tmp_path.display()).green()
                );
                println!(
                    "{}",
                    format!("✅ Temp file auto-deletes after {} s.", TEMP_LIFETIME_SECS).green()
                );

                thread::sleep(Duration::from_secs(TEMP_LIFETIME_SECS));

                match fs::remove_file(&tmp_path) {
                    Ok(_) => println!("{}", "✅ Temp file deleted.".green()),
                    Err(e) => {
                        let msg =
                            format!("Failed to delete temp file '{}': {}", tmp_path.display(), e);
                        json_logger
                            .log_error_event("wallet", "WalletUtilsDeleteTempFileFailed", &msg)
                            .ok();
                        println!(
                            "{}",
                            "⚠️  Failed to delete temp file – please remove it manually.".yellow()
                        );
                    }
                }

                Ok(())
            }

            "2" => {
                let mut priv_key_hex = Password::new()
                    .with_prompt("🔑 Enter your **private key** (input is hidden)")
                    .allow_empty_password(false)
                    .interact()
                    .map_err(|e| ErrorDetection::IoError {
                        message: e.to_string(),
                        code: None,
                        source: Some(Box::new(e)),
                    })?;

                let trimmed = priv_key_hex.trim();
                if trimmed.is_empty() {
                    priv_key_hex.zeroize();
                    return Err(ErrorDetection::ValidationError {
                        message: "❌ Private key cannot be empty.".into(),
                        tx_id: None,
                    });
                }

                if trimmed.len() > GlobalConfiguration::MAX_PRIVKEY_HEX_INPUT_LEN {
                    priv_key_hex.zeroize();
                    return Err(ErrorDetection::ValidationError {
                        message: "❌ Private key input too long.".into(),
                        tx_id: None,
                    });
                }

                if trimmed.len() != GlobalConfiguration::MLDSA65_SECRET_HEX_LEN {
                    priv_key_hex.zeroize();
                    return Err(ErrorDetection::ValidationError {
                        message: format!(
                            "❌ Private key must be exactly {} hex characters ({} bytes).",
                            GlobalConfiguration::MLDSA65_SECRET_HEX_LEN,
                            fips204::ml_dsa_65::SK_LEN
                        ),
                        tx_id: None,
                    });
                }

                let mut priv_key_bytes = hex::decode(trimmed).map_err(|e| {
                    priv_key_hex.zeroize();
                    ErrorDetection::ValidationError {
                        message: format!("❌ Private key is not valid hex: {e}"),
                        tx_id: None,
                    }
                })?;

                priv_key_hex.zeroize();

                if priv_key_bytes.len() != fips204::ml_dsa_65::SK_LEN {
                    priv_key_bytes.zeroize();
                    return Err(ErrorDetection::ValidationError {
                        message: format!(
                            "❌ Private key must decode to exactly {} bytes.",
                            fips204::ml_dsa_65::SK_LEN
                        ),
                        tx_id: None,
                    });
                }

                let recovered_addr = MLDSA65Wallet::address_from_secret_bytes(&priv_key_bytes)
                    .map_err(|e| {
                        priv_key_bytes.zeroize();
                        ErrorDetection::ValidationError {
                            message: format!("❌ Unable to derive address: {e}"),
                            tx_id: None,
                        }
                    })?;

                priv_key_bytes.zeroize();

                println!(
                    "{} {}",
                    "✅ Recovered public address:".green(),
                    recovered_addr
                );
                Ok(())
            }

            _ => {
                println!("{}", "❌ Returning to the menu.".red());
                Ok(())
            }
        }
    }
}

impl Default for S13WalletUtilities {
    fn default() -> Self {
        Self::new()
    }
}
