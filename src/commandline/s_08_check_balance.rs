//! src/commandline/s_08_check_balance.rs

use crate::blockchain::transaction_005_tx_account_tree::AccountModelTree;
use crate::cryptography::ml_dsa_65_005_encryption::Cryption;
use crate::runtime::p2p_006_sync_runtime::NodeOpts;
use crate::storage::rocksdb_000_directory::DirectoryDB;
use crate::storage::rocksdb_005_manager::RockDBManager;
use crate::utility::alpha_001_global_configuration::GlobalConfiguration;
use crate::utility::alpha_002_error_detection_system::ErrorDetection;
use crate::utility::helper::{canon_wallet_id_checked, format_remzar_trim};
use crate::utility::logging_data::JsonLogger;

use colored::Colorize;
use dialoguer::Password;
use fips204::ml_dsa_65;
use fips204::traits::{SerDes, Signer};
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::sync::Arc;
use zeroize::{Zeroize, Zeroizing};

#[derive(Default)]
pub struct S08CheckBalance;

impl S08CheckBalance {
    pub fn new() -> Self {
        Self
    }

    #[inline]
    fn max_attempts() -> usize {
        GlobalConfiguration::MAX_ATTEMPTS as usize
    }

    #[inline]
    fn flush_stdout(stage: &'static str, json_logger: &JsonLogger) -> Result<(), ErrorDetection> {
        io::stdout().flush().map_err(|e| {
            let msg = format!("Failed to flush stdout ({stage}): {e}");
            json_logger
                .log_error_event("balance", "CheckBalanceFlushStdoutFailed", &msg)
                .ok();
            ErrorDetection::IoError {
                message: msg,
                code: e.raw_os_error(),
                source: Some(Box::new(e)),
            }
        })
    }

    #[inline]
    fn read_line_capped(
        prompt: &str,
        cap: usize,
        stage: &'static str,
        json_logger: &JsonLogger,
    ) -> Result<String, ErrorDetection> {
        print!("{prompt}");
        Self::flush_stdout(stage, json_logger)?;

        let mut s = String::new();
        io::stdin().read_line(&mut s).map_err(|e| {
            let msg = format!("Failed to read input ({stage}): {e}");
            json_logger
                .log_error_event("balance", "CheckBalanceReadInputFailed", &msg)
                .ok();
            ErrorDetection::IoError {
                message: msg,
                code: e.raw_os_error(),
                source: Some(Box::new(e)),
            }
        })?;

        if s.len() > cap {
            let msg = format!("Input too long ({stage}): max {} chars", cap);
            json_logger
                .log_error_event("balance", "CheckBalanceInputTooLong", &msg)
                .ok();
            return Err(ErrorDetection::ValidationError {
                message: msg,
                tx_id: None,
            });
        }

        Ok(s.trim().to_string())
    }

    fn read_yes_no_bounded(
        prompt: &str,
        stage: &'static str,
        json_logger: &JsonLogger,
    ) -> Result<bool, ErrorDetection> {
        let mut attempts = 0usize;

        loop {
            attempts = attempts.saturating_add(1);
            if attempts > Self::max_attempts() {
                let msg = "Too many invalid attempts. Returning to menu.".to_string();
                json_logger
                    .log_error_event("balance", "CheckBalanceTooManyYesNoAttempts", &msg)
                    .ok();
                println!("{}", format!("❌ {}", msg).red());
                return Ok(false);
            }

            let line = match Self::read_line_capped(
                prompt,
                GlobalConfiguration::MAX_YN_INPUT_LEN,
                stage,
                json_logger,
            ) {
                Ok(v) => v,
                Err(ErrorDetection::ValidationError { message, .. }) => {
                    println!("{}", format!("❌ {}", message).red());
                    continue;
                }
                Err(e) => return Err(e),
            };

            match line.trim().to_ascii_lowercase().as_str() {
                "yes" | "y" => return Ok(true),
                "no" | "n" => return Ok(false),
                _ => println!("{}", "❌ Please type 'yes' or 'no'.".red()),
            }
        }
    }

    fn read_wallet_address_bounded(
        json_logger: &JsonLogger,
    ) -> Result<Option<String>, ErrorDetection> {
        let mut attempts = 0usize;

        loop {
            attempts = attempts.saturating_add(1);
            if attempts > Self::max_attempts() {
                let msg = "Too many invalid wallet attempts. Returning to menu.".to_string();
                json_logger
                    .log_error_event("balance", "CheckBalanceTooManyWalletAttempts", &msg)
                    .ok();
                println!("{}", format!("❌ {}", msg).red());
                return Ok(None);
            }

            let raw = match Self::read_line_capped(
                "🏦 Enter your wallet address (or type \"exit\" to return): ",
                GlobalConfiguration::MAX_INPUT_BYTES,
                "check_balance.wallet.read",
                json_logger,
            ) {
                Ok(v) => v,
                Err(ErrorDetection::ValidationError { message, .. }) => {
                    println!("{}", format!("❌ {}", message).red());
                    continue;
                }
                Err(e) => return Err(e),
            };

            if raw.eq_ignore_ascii_case("exit") {
                return Ok(None);
            }

            match canon_wallet_id_checked(&raw) {
                Ok(addr) => return Ok(Some(addr)),
                Err(e) => {
                    let msg = format!("Wallet address is invalid: {e}");
                    json_logger
                        .log_error_event("balance", "CheckBalanceInvalidWalletAddress", &msg)
                        .ok();
                    println!("{}", "❌ Wallet address is invalid or incomplete.".red());
                }
            }
        }
    }

    fn read_confirmed_passphrase(
        json_logger: &JsonLogger,
    ) -> Result<Option<String>, ErrorDetection> {
        let mut attempts = 0usize;

        loop {
            attempts = attempts.saturating_add(1);
            if attempts > GlobalConfiguration::MAX_PASS_PROMPTS {
                let msg = "Too many failed passphrase attempts. Returning to menu.".to_string();
                json_logger
                    .log_error_event("balance", "CheckBalancePassphraseTooManyAttempts", &msg)
                    .ok();
                println!("{}", format!("❌ {}", msg).red());
                return Ok(None);
            }

            let mut passphrase = match Password::new()
                .with_prompt("🔒 Please enter your wallet passphrase")
                .allow_empty_password(false)
                .interact()
            {
                Ok(p) => p,
                Err(e) => {
                    let msg = format!("Failed to read passphrase: {e}");
                    json_logger
                        .log_error_event("balance", "CheckBalancePassphraseReadFailed", &msg)
                        .ok();
                    return Err(ErrorDetection::IoError {
                        message: msg,
                        code: None,
                        source: Some(Box::new(e)),
                    });
                }
            };

            if passphrase.len() > Cryption::MAX_PASSPHRASE_BYTES_ABSOLUTE {
                passphrase.zeroize();
                println!("{}", "❌ Passphrase is too large. Please try again.".red());
                continue;
            }

            let mut confirm_passphrase = match Password::new()
                .with_prompt("🔒 Please confirm your wallet passphrase")
                .allow_empty_password(false)
                .interact()
            {
                Ok(p) => p,
                Err(e) => {
                    passphrase.zeroize();
                    let msg = format!("Failed to read passphrase confirmation: {e}");
                    json_logger
                        .log_error_event("balance", "CheckBalancePassphraseConfirmReadFailed", &msg)
                        .ok();
                    return Err(ErrorDetection::IoError {
                        message: msg,
                        code: None,
                        source: Some(Box::new(e)),
                    });
                }
            };

            if confirm_passphrase.len() > Cryption::MAX_PASSPHRASE_BYTES_ABSOLUTE {
                passphrase.zeroize();
                confirm_passphrase.zeroize();
                println!("{}", "❌ Passphrase is too large. Please try again.".red());
                continue;
            }

            if passphrase != confirm_passphrase {
                passphrase.zeroize();
                confirm_passphrase.zeroize();
                println!("{}", "❌ Passphrases do not match. Please try again.".red());
                continue;
            }

            if passphrase.trim().is_empty() {
                passphrase.zeroize();
                confirm_passphrase.zeroize();
                println!(
                    "{}",
                    "❌ Passphrase cannot be empty. Please try again.".red()
                );
                continue;
            }

            confirm_passphrase.zeroize();
            return Ok(Some(passphrase));
        }
    }

    fn load_signing_key_from_wallet(
        wallet_file: &Path,
        passphrase: &str,
        expected_wallet_addr: &str,
        json_logger: &JsonLogger,
    ) -> Result<ml_dsa_65::PrivateKey, ErrorDetection> {
        let meta = fs::metadata(wallet_file).map_err(|e| {
            let msg = format!("Failed to stat wallet file {}: {e}", wallet_file.display());
            json_logger
                .log_error_event("balance", "CheckBalanceWalletStatFailed", &msg)
                .ok();
            ErrorDetection::IoError {
                message: msg,
                code: e.raw_os_error(),
                source: Some(Box::new(e)),
            }
        })?;

        if !meta.is_file() {
            return Err(ErrorDetection::ValidationError {
                message: "Wallet path is not a regular file.".to_string(),
                tx_id: None,
            });
        }

        let enc_len = match usize::try_from(meta.len()) {
            Ok(v) => v,
            Err(_) => {
                return Err(ErrorDetection::ValidationError {
                    message: "Wallet file size is too large for this platform.".to_string(),
                    tx_id: None,
                });
            }
        };

        if enc_len < Cryption::MIN_ENCRYPTED_BLOB_FOR_ML_DSA_SECRET_BYTES {
            return Err(ErrorDetection::ValidationError {
                message: "Wallet file is too small or corrupt.".to_string(),
                tx_id: None,
            });
        }

        if enc_len > GlobalConfiguration::MAX_ENCRYPTED_BLOB_BYTES {
            return Err(ErrorDetection::ValidationError {
                message: "Wallet file exceeds encrypted blob size limits.".to_string(),
                tx_id: None,
            });
        }

        let mut encrypted = fs::read(wallet_file).map_err(|e| {
            let msg = format!("Failed to read wallet file {}: {e}", wallet_file.display());
            json_logger
                .log_error_event("balance", "CheckBalanceWalletReadFailed", &msg)
                .ok();
            ErrorDetection::IoError {
                message: msg,
                code: e.raw_os_error(),
                source: Some(Box::new(e)),
            }
        })?;

        let plaintext: Zeroizing<Vec<u8>> =
            match Cryption::decrypt_private_key_bytes(&encrypted, passphrase) {
                Ok(p) => Zeroizing::new(p),
                Err(e) => {
                    encrypted.zeroize();
                    let msg = format!("Failed to decrypt wallet file: {e}");
                    json_logger
                        .log_error_event("balance", "CheckBalanceWalletDecryptFailed", &msg)
                        .ok();
                    return Err(ErrorDetection::ValidationError {
                    message:
                        "Wallet authentication failed. Invalid passphrase or corrupt wallet file."
                            .to_string(),
                    tx_id: None,
                });
                }
            };

        encrypted.zeroize();

        let signing_key = if plaintext.len() == ml_dsa_65::SK_LEN {
            let sk_arr: [u8; ml_dsa_65::SK_LEN] =
                plaintext
                    .as_slice()
                    .try_into()
                    .map_err(|_| ErrorDetection::ValidationError {
                        message: format!(
                            "Failed to convert decrypted secret to [u8; {}]",
                            ml_dsa_65::SK_LEN
                        ),
                        tx_id: None,
                    })?;

            ml_dsa_65::PrivateKey::try_from_bytes(sk_arr).map_err(|e| {
                ErrorDetection::CryptographicError {
                    message: format!("Invalid ML-DSA-65 secret key bytes: {e}"),
                }
            })?
        } else {
            let maybe_utf8 =
                std::str::from_utf8(plaintext.as_slice()).map_err(|_| {
                    ErrorDetection::ValidationError {
                        message: format!(
                            "Decrypted secret is not {} raw bytes and is not valid UTF-8; wallet format unknown/corrupt",
                            ml_dsa_65::SK_LEN
                        ),
                        tx_id: None,
                    }
                })?;

            let secret_hex = maybe_utf8.trim();

            if secret_hex.len() != ml_dsa_65::SK_LEN * 2
                || !secret_hex.chars().all(|c| c.is_ascii_hexdigit())
            {
                return Err(ErrorDetection::ValidationError {
                    message: format!(
                        "Decrypted secret has unexpected length/format: got {} bytes (raw) / {} chars (utf8)",
                        plaintext.len(),
                        secret_hex.len()
                    ),
                    tx_id: None,
                });
            }

            let mut secret_bytes =
                hex::decode(secret_hex).map_err(|e| ErrorDetection::ValidationError {
                    message: format!("Cannot decode decrypted secret hex: {e:?}"),
                    tx_id: None,
                })?;

            if secret_bytes.len() != ml_dsa_65::SK_LEN {
                secret_bytes.zeroize();
                return Err(ErrorDetection::ValidationError {
                    message: format!(
                        "Decoded secret must be {} bytes, got {}",
                        ml_dsa_65::SK_LEN,
                        secret_bytes.len()
                    ),
                    tx_id: None,
                });
            }

            let sk_arr: [u8; ml_dsa_65::SK_LEN] =
                secret_bytes.as_slice().try_into().map_err(|_| {
                    ErrorDetection::ValidationError {
                        message: format!(
                            "Failed to convert decoded secret to [u8; {}]",
                            ml_dsa_65::SK_LEN
                        ),
                        tx_id: None,
                    }
                })?;

            secret_bytes.zeroize();

            ml_dsa_65::PrivateKey::try_from_bytes(sk_arr).map_err(|e| {
                ErrorDetection::CryptographicError {
                    message: format!("Invalid ML-DSA-65 secret key bytes: {e}"),
                }
            })?
        };

        let verifying_key = signing_key.get_public_key();
        let public_bytes = verifying_key.into_bytes();

        let derived_wallet =
            crate::utility::helper::derive_wallet_id_from_pubkey_bytes(&public_bytes);
        let expected_wallet = canon_wallet_id_checked(expected_wallet_addr)?;

        if derived_wallet != expected_wallet {
            return Err(ErrorDetection::ValidationError {
                message: "Wallet file does not belong to the entered wallet address.".to_string(),
                tx_id: None,
            });
        }

        Ok(signing_key)
    }

    fn authenticate_local_wallet(
        opts: &NodeOpts,
        wallet_addr: &str,
        passphrase: &str,
        json_logger: &JsonLogger,
    ) -> Result<(), ErrorDetection> {
        let directory = DirectoryDB::from_node_opts(opts).map_err(|e| {
            let msg = format!("Failed to initialize directories: {e}");
            json_logger
                .log_error_event("balance", "CheckBalanceInitDirectoriesFailed", &msg)
                .ok();
            ErrorDetection::IoError {
                message: msg,
                code: None,
                source: None,
            }
        })?;

        directory.create_wallets_directory().map_err(|e| {
            let msg = format!("Failed to create/check wallets directory: {e}");
            json_logger
                .log_error_event("balance", "CheckBalanceCreateWalletDirFailed", &msg)
                .ok();
            ErrorDetection::IoError {
                message: msg,
                code: None,
                source: None,
            }
        })?;

        let wallet_file = directory
            .wallets_path
            .join(format!("{}.wallet", wallet_addr));

        if !wallet_file.exists() {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Wallet file not found for this address: {}",
                    wallet_file.display()
                ),
                tx_id: None,
            });
        }

        let signing_key =
            Self::load_signing_key_from_wallet(&wallet_file, passphrase, wallet_addr, json_logger)?;

        drop(signing_key);
        Ok(())
    }

    fn resolve_balance_micro(
        wallet_addr: &str,
        db_manager: &Arc<RockDBManager>,
        chain_opt: &Option<AccountModelTree>,
        json_logger: &JsonLogger,
    ) -> Result<u64, ErrorDetection> {
        match db_manager.read(
            GlobalConfiguration::ACCOUNT_COLUMN_NAME,
            wallet_addr.as_bytes(),
        ) {
            Ok(Some(bytes)) => match postcard::from_bytes::<u64>(&bytes) {
                Ok(v) => Ok(v),
                Err(e) => {
                    let deserialize_msg = format!(
                        "Corrupt balance entry for wallet {} in {}: {}",
                        wallet_addr,
                        GlobalConfiguration::ACCOUNT_COLUMN_NAME,
                        e
                    );
                    json_logger
                        .log_error_event(
                            "balance",
                            "CheckBalanceDeserializeFailed",
                            &deserialize_msg,
                        )
                        .ok();

                    if let Some(mut chain) = chain_opt.clone() {
                        chain.reload_from_db();
                        Ok(chain.get_balance(wallet_addr))
                    } else {
                        match db_manager.load_state() {
                            Ok(tree) => Ok(tree.get_balance(wallet_addr)),
                            Err(load_err) => {
                                let recover_msg = format!(
                                    "Failed to recover balance from state for {}: {}",
                                    wallet_addr, load_err
                                );
                                json_logger
                                    .log_error_event(
                                        "balance",
                                        "CheckBalanceLoadStateFailed",
                                        &recover_msg,
                                    )
                                    .ok();
                                Ok(0)
                            }
                        }
                    }
                }
            },

            Ok(None) => {
                if let Some(mut chain) = chain_opt.clone() {
                    chain.reload_from_db();
                    Ok(chain.get_balance(wallet_addr))
                } else {
                    match db_manager.load_state() {
                        Ok(tree) => Ok(tree.get_balance(wallet_addr)),
                        Err(e) => {
                            let load_state_msg = format!(
                                "Failed to load state snapshot while checking balance for {}: {}",
                                wallet_addr, e
                            );
                            json_logger
                                .log_error_event(
                                    "balance",
                                    "CheckBalanceLoadStateFailed",
                                    &load_state_msg,
                                )
                                .ok();
                            Ok(0)
                        }
                    }
                }
            }

            Err(e) => {
                let read_balance_msg = format!(
                    "Failed to read wallet balance from {}: {}",
                    GlobalConfiguration::ACCOUNT_COLUMN_NAME,
                    e
                );
                json_logger
                    .log_error_event(
                        "balance",
                        "CheckBalanceReadBalanceFailed",
                        &read_balance_msg,
                    )
                    .ok();
                Err(ErrorDetection::DatabaseError {
                    details: read_balance_msg,
                })
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 08) Check Balance – local wallet auth + authoritative balance read
    // ─────────────────────────────────────────────────────────────────────────────
    pub fn check_balance(
        &self,
        opts: &NodeOpts,
        db_manager: Arc<RockDBManager>,
        chain_opt: Option<AccountModelTree>,
        json_logger: &JsonLogger,
    ) -> Result<(), ErrorDetection> {
        println!();
        println!("{}", "🔹 Wallet Balance".cyan());
        println!(
            "{}",
            "🔐 Authentication is required before viewing a locally stored wallet balance.".cyan()
        );

        let proceed = Self::read_yes_no_bounded(
            "💰 Do you want to check your wallet balance? (yes/no): ",
            "check_balance.confirm",
            json_logger,
        )?;
        if !proceed {
            println!("{}", "❌ Returning to menu.".yellow());
            return Ok(());
        }

        let wallet_addr = match Self::read_wallet_address_bounded(json_logger)? {
            Some(addr) => addr,
            None => {
                println!("{}", "❌ Returning to menu.".yellow());
                return Ok(());
            }
        };

        let proceed_security = Self::read_yes_no_bounded(
            "⚠️ For security, you must authenticate with your wallet passphrase.\n\
NOTE: When entering your password, nothing will be shown as you type—just a blinking cursor. This is normal for security.\n\
Proceed? (yes/no): ",
            "check_balance.security_confirm",
            json_logger,
        )?;
        if !proceed_security {
            println!("{}", "❌ Returning to menu.".yellow());
            return Ok(());
        }

        let mut passphrase = match Self::read_confirmed_passphrase(json_logger)? {
            Some(p) => p,
            None => return Ok(()),
        };

        let auth_result =
            Self::authenticate_local_wallet(opts, &wallet_addr, &passphrase, json_logger);
        passphrase.zeroize();

        match auth_result {
            Ok(()) => {
                println!("{}", "✅ Wallet authentication successful.".green());
            }
            Err(e) => {
                println!("{}", format!("❌ {}", e).red());
                return Ok(());
            }
        }

        let balance_micro =
            Self::resolve_balance_micro(&wallet_addr, &db_manager, &chain_opt, json_logger)?;

        println!(
            "{} {}",
            "Wallet balance:".green(),
            format_remzar_trim(balance_micro).yellow(),
        );

        Ok(())
    }
}
