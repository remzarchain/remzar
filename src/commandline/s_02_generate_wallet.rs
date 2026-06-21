//! src/commandline/s_02_generate_wallet.rs
//! 02. Generate Wallet (interactive wrapper)

use crate::cryptography::ml_dsa_65_006_edwallet::MLDSA65Wallet;
use crate::privacy::privacy_001_private_receive_wallet::{
    PrivateRW, PrivateReceiveCreateOwnedRequest,
};
use crate::privacy::privacy_002_private_receive_invoice::PrivateRI;
use crate::privacy::privacy_003_private_wallet_index::PrivateWI;
use crate::runtime::p2p_006_sync_runtime::NodeOpts;
use crate::storage::rocksdb_000_directory::DirectoryDB;
use crate::utility::alpha_001_global_configuration::GlobalConfiguration;
use crate::utility::alpha_002_error_detection_system::ErrorDetection;
use crate::utility::helper::canon_wallet_id_checked;
use crate::utility::logging_data::JsonLogger;
use crate::utility::wallet_qr_code::QRWallet;

use colored::Colorize;
use dialoguer::Password;
use std::fs;
use std::io::ErrorKind;
use zeroize::Zeroize;

#[derive(Default)]
pub struct S02GenerateWallet;

impl S02GenerateWallet {
    pub fn new() -> Self {
        Self
    }

    fn read_line_capped_prompt(prompt: &str, cap: usize) -> Result<String, ErrorDetection> {
        use std::io::{self, Write};

        print!("{prompt}");
        io::stdout().flush().map_err(|e| ErrorDetection::IoError {
            message: format!("Failed to flush stdout: {}", e),
            code: e.raw_os_error(),
            source: Some(Box::new(e)),
        })?;

        let mut s = String::new();
        io::stdin()
            .read_line(&mut s)
            .map_err(|e| ErrorDetection::IoError {
                message: format!("Failed to read input: {}", e),
                code: e.raw_os_error(),
                source: Some(Box::new(e)),
            })?;

        if s.len() > cap {
            return Err(ErrorDetection::ValidationError {
                message: format!("Input too long (max {} chars)", cap),
                tx_id: None,
            });
        }

        Ok(s.trim().to_string())
    }

    fn confirm_yes_no(prompt: &str) -> Result<bool, ErrorDetection> {
        loop {
            let answer =
                Self::read_line_capped_prompt(prompt, GlobalConfiguration::MAX_YN_INPUT_LEN)?;

            match answer.to_lowercase().as_str() {
                "yes" => return Ok(true),
                "no" => return Ok(false),
                _ => println!(
                    "{}",
                    "❌ Invalid response. Please type 'yes' or 'no'.".red()
                ),
            }
        }
    }

    fn prompt_wallet_qr_passphrase(json_logger: &JsonLogger) -> Result<String, ErrorDetection> {
        let mut attempts = 0usize;

        loop {
            attempts = attempts.saturating_add(1);

            if attempts > GlobalConfiguration::MAX_PASS_PROMPTS {
                let msg = "Too many failed wallet QR passphrase attempts; aborting.".to_string();

                json_logger
                    .log_error_event("wallet_qr", "WalletQrPassphraseTooManyAttempts", &msg)
                    .ok();

                return Err(ErrorDetection::ValidationError {
                    message: msg,
                    tx_id: None,
                });
            }

            let mut input_passphrase = match Password::new()
                .with_prompt("🔒 Enter passphrase for wallet QR authentication")
                .allow_empty_password(false)
                .interact()
            {
                Ok(pass) => pass,
                Err(e) => {
                    let msg = format!("Failed to read wallet QR passphrase: {e}");

                    json_logger
                        .log_error_event("wallet_qr", "WalletQrPassphraseReadFailed", &msg)
                        .ok();

                    return Err(ErrorDetection::IoError {
                        message: msg,
                        code: None,
                        source: Some(Box::new(e)),
                    });
                }
            };

            let mut confirm_passphrase = match Password::new()
                .with_prompt("🔒 Confirm wallet passphrase")
                .allow_empty_password(false)
                .interact()
            {
                Ok(pass) => pass,
                Err(e) => {
                    input_passphrase.zeroize();

                    let msg = format!("Failed to read wallet QR passphrase confirmation: {e}");

                    json_logger
                        .log_error_event("wallet_qr", "WalletQrPassphraseConfirmReadFailed", &msg)
                        .ok();

                    return Err(ErrorDetection::IoError {
                        message: msg,
                        code: None,
                        source: Some(Box::new(e)),
                    });
                }
            };

            if input_passphrase != confirm_passphrase {
                input_passphrase.zeroize();
                confirm_passphrase.zeroize();

                println!("{}", "❌ Passphrases do not match. Please try again.".red());
                continue;
            }

            confirm_passphrase.zeroize();
            return Ok(input_passphrase);
        }
    }

    fn generate_wallet_qr_interactive(&mut self, opts: &NodeOpts, json_logger: &JsonLogger) {
        println!();
        println!("{}", "🔹 Generate QR Code for Wallet Address".cyan());
        println!(
            "{}",
            "This creates a public QR code PNG that contains ONLY the wallet address.".yellow()
        );

        let confirmed = match Self::confirm_yes_no(
            "Please enter your wallet address you want to generate a QR Code for. (yes/no): ",
        ) {
            Ok(v) => v,
            Err(e) => {
                println!(
                    "{}",
                    format!("❌ Wallet QR confirmation failed: {e:?}").red()
                );

                json_logger
                    .log_error_event("wallet_qr", "WalletQrConfirmFailed", &format!("{e:?}"))
                    .ok();

                return;
            }
        };

        if !confirmed {
            println!(
                "{}",
                "↩️  Wallet QR generation cancelled, returning to menu.".yellow()
            );
            return;
        }

        let wallet_in = match Self::read_line_capped_prompt(
            "Enter wallet: ",
            GlobalConfiguration::MAX_INPUT_BYTES,
        ) {
            Ok(v) => v,
            Err(e) => {
                println!(
                    "{}",
                    format!("❌ Failed to read wallet address: {e:?}").red()
                );

                json_logger
                    .log_error_event("wallet_qr", "WalletQrAddressReadFailed", &format!("{e:?}"))
                    .ok();

                return;
            }
        };

        let wallet_address = match canon_wallet_id_checked(&wallet_in) {
            Ok(v) => v,
            Err(e) => {
                println!("{}", "❌ Invalid wallet address.".red());
                println!("{}", format!("Details: {e:?}").red());
                println!("{}", "No wallet QR code was created.".yellow());

                json_logger
                    .log_error_event("wallet_qr", "WalletQrAddressInvalid", &format!("{e:?}"))
                    .ok();

                return;
            }
        };

        let mut passphrase = match Self::prompt_wallet_qr_passphrase(json_logger) {
            Ok(passphrase) => passphrase,
            Err(e) => {
                println!("{}", "❌ Wallet QR passphrase failed.".red());
                println!("{}", format!("Details: {e:?}").red());
                println!("{}", "No wallet QR code was created.".yellow());

                json_logger
                    .log_error_event("wallet_qr", "WalletQrPassphraseFailed", &format!("{e:?}"))
                    .ok();

                return;
            }
        };

        let receipt = match QRWallet::generate_for_owned_wallet(opts, &wallet_address, &passphrase)
        {
            Ok(receipt) => {
                passphrase.zeroize();
                receipt
            }
            Err(e) => {
                passphrase.zeroize();

                println!("{}", "❌ Wallet QR generation failed.".red());
                println!("{}", format!("Details: {e:?}").red());
                println!(
                    "{}",
                    "No wallet QR code was created. The wallet file/passphrase must match."
                        .yellow()
                );

                json_logger
                    .log_error_event("wallet_qr", "WalletQrGenerateFailed", &format!("{e:?}"))
                    .ok();

                return;
            }
        };

        println!();
        println!("{}", "✅ Wallet QR code generated successfully.".green());
        println!("  Wallet address: {}", receipt.wallet_address);
        println!("  QR code PNG:    {}", receipt.qr_png_path.display());
        println!("  QR payload len: {}", receipt.qr_payload_bytes_len);
        println!(
            "{}",
            "  QR scan payload: ONLY the public wallet address above.".green()
        );
    }

    fn prompt_private_receive_passphrase(
        json_logger: &JsonLogger,
    ) -> Result<String, ErrorDetection> {
        let mut attempts = 0usize;

        loop {
            attempts = attempts.saturating_add(1);

            if attempts > GlobalConfiguration::MAX_PASS_PROMPTS {
                let msg = "Too many failed private receive wallet passphrase attempts; aborting."
                    .to_string();

                json_logger
                    .log_error_event(
                        "private_receive",
                        "PrivateReceivePassphraseTooManyAttempts",
                        &msg,
                    )
                    .ok();

                return Err(ErrorDetection::ValidationError {
                    message: msg,
                    tx_id: None,
                });
            }

            let mut input_passphrase = match Password::new()
                .with_prompt("🔒 Enter passphrase for this private receive wallet")
                .allow_empty_password(false)
                .interact()
            {
                Ok(pass) => pass,
                Err(e) => {
                    let msg = format!("Failed to read private receive passphrase: {e}");

                    json_logger
                        .log_error_event(
                            "private_receive",
                            "PrivateReceivePassphraseReadFailed",
                            &msg,
                        )
                        .ok();

                    return Err(ErrorDetection::IoError {
                        message: msg,
                        code: None,
                        source: Some(Box::new(e)),
                    });
                }
            };

            let mut confirm_passphrase = match Password::new()
                .with_prompt("🔒 Confirm private receive wallet passphrase")
                .allow_empty_password(false)
                .interact()
            {
                Ok(pass) => pass,
                Err(e) => {
                    input_passphrase.zeroize();

                    let msg =
                        format!("Failed to read private receive passphrase confirmation: {e}");

                    json_logger
                        .log_error_event(
                            "private_receive",
                            "PrivateReceivePassphraseConfirmReadFailed",
                            &msg,
                        )
                        .ok();

                    return Err(ErrorDetection::IoError {
                        message: msg,
                        code: None,
                        source: Some(Box::new(e)),
                    });
                }
            };

            if input_passphrase != confirm_passphrase {
                input_passphrase.zeroize();
                confirm_passphrase.zeroize();

                println!("{}", "❌ Passphrases do not match. Please try again.".red());
                continue;
            }

            confirm_passphrase.zeroize();
            return Ok(input_passphrase);
        }
    }

    fn generate_private_receive_interactive(
        &mut self,
        opts: &NodeOpts,
        json_logger: &JsonLogger,
    ) -> Result<(), ErrorDetection> {
        println!();
        println!("{}", "🔹 Generate Private Receive Address".cyan());
        println!(
            "{}",
            "This creates a fresh one-time Remzar wallet address for receiving coins privately."
                .yellow()
        );
        println!(
            "{}",
            "Privacy limit: this hides your main receiver wallet from the chain, but it does NOT hide sender, amount, or timestamp."
                .yellow()
        );

        let confirmed = match Self::confirm_yes_no(
            "Do you want to create a private receive address now? (yes/no): ",
        ) {
            Ok(v) => v,
            Err(e) => {
                println!(
                    "{}",
                    format!("❌ Private receive confirmation failed: {e:?}").red()
                );

                json_logger
                    .log_error_event(
                        "private_receive",
                        "PrivateReceiveConfirmFailed",
                        &format!("{e:?}"),
                    )
                    .ok();

                return Err(e);
            }
        };

        if !confirmed {
            println!(
                "{}",
                "↩️  Private receive address generation cancelled, returning to menu.".yellow()
            );
            return Ok(());
        }

        let owner_wallet_in = match Self::read_line_capped_prompt(
            "Enter your MAIN owner wallet address: ",
            GlobalConfiguration::MAX_INPUT_BYTES,
        ) {
            Ok(v) => v,
            Err(e) => {
                println!(
                    "{}",
                    format!("❌ Failed to read owner wallet address: {e:?}").red()
                );

                json_logger
                    .log_error_event(
                        "private_receive",
                        "PrivateReceiveOwnerWalletReadFailed",
                        &format!("{e:?}"),
                    )
                    .ok();

                return Err(e);
            }
        };

        let owner_wallet = match canon_wallet_id_checked(&owner_wallet_in) {
            Ok(v) => v,
            Err(e) => {
                let msg = format!("Invalid owner wallet address: {e:?}");

                println!("{}", "❌ Invalid owner wallet address.".red());
                println!("{}", format!("Details: {e:?}").red());
                println!("{}", "No private receive address was created.".yellow());

                json_logger
                    .log_error_event("private_receive", "PrivateReceiveOwnerWalletInvalid", &msg)
                    .ok();

                return Err(ErrorDetection::ValidationError {
                    message: msg,
                    tx_id: None,
                });
            }
        };

        println!();
        println!(
            "{}",
            "The private receive wallet will be saved as a normal encrypted .wallet file.".yellow()
        );
        println!(
            "{}",
            "Use a passphrase you will remember. You need it to spend from this one-time wallet."
                .yellow()
        );

        let passphrase = match Self::prompt_private_receive_passphrase(json_logger) {
            Ok(v) => v,
            Err(e) => {
                println!("{}", "❌ Private receive passphrase failed.".red());
                println!("{}", format!("Details: {e:?}").red());
                println!("{}", "No private receive address was created.".yellow());

                json_logger
                    .log_error_event(
                        "private_receive",
                        "PrivateReceivePassphraseFailed",
                        &format!("{e:?}"),
                    )
                    .ok();

                return Err(e);
            }
        };

        let receipt = match PrivateRW::new().create_receive_wallet_owned(
            opts,
            PrivateReceiveCreateOwnedRequest {
                owner_wallet,
                passphrase,
                require_owner_wallet_file: true,
            },
        ) {
            Ok(receipt) => receipt,
            Err(e) => {
                println!("{}", "❌ Private receive wallet generation failed.".red());
                println!("{}", format!("Details: {e:?}").red());
                println!(
                    "{}",
                    "No private receive address was created. Make sure the owner wallet file exists and the address is correct."
                        .yellow()
                );

                json_logger
                    .log_error_event(
                        "private_receive",
                        "PrivateReceiveWalletCreateFailed",
                        &format!("{e:?}"),
                    )
                    .ok();

                return Err(e);
            }
        };

        let preview = match PrivateRI::display_preview(&receipt.invoice) {
            Ok(v) => v,
            Err(e) => {
                println!(
                    "{}",
                    format!("⚠️ Private receive invoice preview failed: {e:?}").yellow()
                );

                json_logger
                    .log_error_event(
                        "private_receive",
                        "PrivateReceiveInvoicePreviewFailed",
                        &format!("{e:?}"),
                    )
                    .ok();

                "<preview unavailable>".to_string()
            }
        };

        let indexed_entry = match PrivateWI::new().add_from_receipt(
            opts,
            &receipt,
            Some("private receive address"),
            Some("created from s_02_generate_wallet"),
            true,
        ) {
            Ok(entry) => entry,
            Err(e) => {
                println!(
                    "{}",
                    "❌ Private receive wallet was created, but indexing failed.".red()
                );
                println!("{}", format!("Details: {e:?}").red());
                println!(
                    "{}",
                    "The one-time wallet file still exists. You may rebuild the private wallet index later from private receive records."
                        .yellow()
                );

                json_logger
                    .log_error_event(
                        "private_receive",
                        "PrivateReceiveWalletIndexFailed",
                        &format!("{e:?}"),
                    )
                    .ok();

                return Err(e);
            }
        };

        println!();
        println!(
            "{}",
            "✅ Private receive address generated successfully.".green()
        );
        println!("  Owner wallet:       {}", receipt.owner_wallet);
        println!("  One-time wallet:    {}", receipt.one_time_wallet);
        println!("  Invoice preview:    {}", preview);
        println!("  Wallet file:        {}", receipt.wallet_file_path);
        println!("  Metadata file:      {}", receipt.metadata_file_path);
        println!("  Indexed wallet:     {}", indexed_entry.one_time_wallet);
        println!();
        println!(
            "{}",
            "Share this private receive invoice with the sender:".green()
        );
        println!("{}", receipt.invoice);
        println!();
        println!(
            "{}",
            "Reminder: the sender will still be public, and the amount will still be public. Your main receiving wallet is hidden because the sender pays the one-time wallet above."
                .yellow()
        );

        Ok(())
    }

    pub fn generate_wallet(
        &mut self,
        opts: &NodeOpts,
        json_logger: &JsonLogger,
    ) -> Result<(), ErrorDetection> {
        fn read_line_capped(prompt: &str, cap: usize) -> Result<String, ErrorDetection> {
            use std::io::{self, Write};

            print!("{prompt}");
            io::stdout().flush().map_err(|e| ErrorDetection::IoError {
                message: format!("Failed to flush stdout: {}", e),
                code: e.raw_os_error(),
                source: Some(Box::new(e)),
            })?;

            let mut s = String::new();
            io::stdin()
                .read_line(&mut s)
                .map_err(|e| ErrorDetection::IoError {
                    message: format!("Failed to read input: {}", e),
                    code: e.raw_os_error(),
                    source: Some(Box::new(e)),
                })?;

            if s.len() > cap {
                return Err(ErrorDetection::ValidationError {
                    message: format!("Input too long (max {} chars)", cap),
                    tx_id: None,
                });
            }

            Ok(s.trim().to_string())
        }

        println!("{}", "🔹 Wallet Generation".cyan());

        // Confirm wallet generation / private receive / wallet QR tools.
        loop {
            let confirm_generate = match read_line_capped(
                "💳 Do you want to generate a new wallet, private receive address, or wallet QR code? (yes/no): ",
                GlobalConfiguration::MAX_YN_INPUT_LEN,
            ) {
                Ok(v) => v,
                Err(e) => {
                    println!("{}", format!("❌ {}", e).red());
                    json_logger
                        .log_error_event(
                            "wallet",
                            "GenerateWalletConfirmInputTooLong",
                            &e.to_string(),
                        )
                        .ok();
                    continue;
                }
            };

            match confirm_generate.to_lowercase().as_str() {
                "yes" => break,
                "no" => return Ok(()),
                _ => println!(
                    "{}",
                    "❌ Invalid response. Please type 'yes' or 'no'.".red()
                ),
            }
        }

        // Mode menu (single / multiple / private receive / wallet QR / exit)
        let batch_count: usize = loop {
            println!("{}", "🔹 Select Wallet Generation Mode".cyan());
            println!("{}", "  [1] Generate Single Wallet".cyan());
            println!("{}", "  [2] Generate Multiple Wallets".cyan());
            println!("{}", "  [3] Generate Private Receive Address".cyan());
            println!("{}", "  [4] Generate QR Code for Wallet Address".cyan());
            println!("{}", "  [5] Exit (Back to Menu)".cyan());

            let choice = match read_line_capped(
                "Enter choice (1-5): ",
                GlobalConfiguration::MAX_MODE_INPUT_LEN,
            ) {
                Ok(v) => v,
                Err(e) => {
                    println!("{}", format!("❌ {}", e).red());
                    json_logger
                        .log_error_event(
                            "wallet",
                            "GenerateWalletModeMenuInputTooLong",
                            &e.to_string(),
                        )
                        .ok();
                    continue;
                }
            };

            match choice.as_str() {
                "1" => break 1usize,
                "2" => {
                    let n: usize = loop {
                        let v = match read_line_capped(
                            "🔢 How many wallets do you want to generate? (2-10): ",
                            GlobalConfiguration::MAX_BATCH_INPUT_LEN,
                        ) {
                            Ok(v) => v,
                            Err(e) => {
                                println!("{}", format!("❌ {}", e).red());
                                json_logger
                                    .log_error_event(
                                        "wallet",
                                        "GenerateWalletBatchCountInputTooLong",
                                        &e.to_string(),
                                    )
                                    .ok();
                                continue;
                            }
                        };

                        match v.parse::<usize>() {
                            Ok(x) if (2..=GlobalConfiguration::MAX_BATCH_WALLETS).contains(&x) => {
                                break x;
                            }
                            Ok(_) => {
                                println!("{}", "❌ Invalid number. Please choose 2 to 10.".red())
                            }
                            Err(_) => {
                                println!("{}", "❌ Invalid number. Please enter digits only.".red())
                            }
                        }
                    };

                    loop {
                        let confirm_batch = match read_line_capped(
                            &format!("🔁 {} wallets will be generated. Proceed? (yes/no): ", n),
                            GlobalConfiguration::MAX_YN_INPUT_LEN,
                        ) {
                            Ok(v) => v,
                            Err(e) => {
                                println!("{}", format!("❌ {}", e).red());
                                json_logger
                                    .log_error_event(
                                        "wallet",
                                        "GenerateWalletBatchConfirmInputTooLong",
                                        &e.to_string(),
                                    )
                                    .ok();
                                continue;
                            }
                        };

                        match confirm_batch.to_lowercase().as_str() {
                            "yes" => break,
                            "no" => return Ok(()),
                            _ => println!(
                                "{}",
                                "❌ Invalid response. Please type 'yes' or 'no'.".red()
                            ),
                        }
                    }

                    break n;
                }
                "3" => {
                    self.generate_private_receive_interactive(opts, json_logger)?;
                    return Ok(());
                }
                "4" => {
                    self.generate_wallet_qr_interactive(opts, json_logger);
                    return Ok(());
                }
                "5" => return Ok(()),
                _ => println!(
                    "{}",
                    "❌ Invalid choice. Please choose 1, 2, 3, 4, or 5.".red()
                ),
            }
        };

        // Recommend a strong passphrase.
        loop {
            let confirm_security = match read_line_capped(
                "⚠️ High recommendation: Use at least 8 characters, including symbols.\n\
    NOTE: When entering your password, nothing will be shown as you type—just a blinking cursor. This is normal for security.\n\
    Proceed? (yes/no): ",
                GlobalConfiguration::MAX_YN_INPUT_LEN,
            ) {
                Ok(v) => v,
                Err(e) => {
                    println!("{}", format!("❌ {}", e).red());
                    json_logger
                        .log_error_event(
                            "wallet",
                            "GenerateWalletSecurityPromptInputTooLong",
                            &e.to_string(),
                        )
                        .ok();
                    continue;
                }
            };

            match confirm_security.to_lowercase().as_str() {
                "yes" => break,
                "no" => return Ok(()),
                _ => println!(
                    "{}",
                    "❌ Invalid response. Please type 'yes' or 'no'.".red()
                ),
            }
        }

        // Passphrase prompt (guard attempts; zeroize on mismatch)
        let mut passphrase = {
            let mut attempts = 0usize;
            loop {
                attempts = attempts.saturating_add(1);
                if attempts > GlobalConfiguration::MAX_PASS_PROMPTS {
                    let msg = "Too many failed passphrase attempts; aborting.".to_string();
                    json_logger
                        .log_error_event("wallet", "GenerateWalletPassphraseTooManyAttempts", &msg)
                        .ok();
                    return Err(ErrorDetection::ValidationError {
                        message: msg,
                        tx_id: None,
                    });
                }

                let mut input_passphrase = match Password::new()
                    .with_prompt("🔒 Enter passphrase for wallet encryption")
                    .allow_empty_password(false)
                    .interact()
                {
                    Ok(pass) => pass,
                    Err(e) => {
                        let msg = format!("Failed to read passphrase: {e}");
                        json_logger
                            .log_error_event("wallet", "GenerateWalletPassphraseReadFailed", &msg)
                            .ok();
                        return Err(ErrorDetection::IoError {
                            message: msg,
                            code: None,
                            source: Some(Box::new(e)),
                        });
                    }
                };

                let mut confirm_passphrase = match Password::new()
                    .with_prompt("🔒 Confirm your passphrase")
                    .allow_empty_password(false)
                    .interact()
                {
                    Ok(pass) => pass,
                    Err(e) => {
                        input_passphrase.zeroize();
                        let msg = format!("Failed to read passphrase confirmation: {e}");
                        json_logger
                            .log_error_event(
                                "wallet",
                                "GenerateWalletPassphraseConfirmReadFailed",
                                &msg,
                            )
                            .ok();
                        return Err(ErrorDetection::IoError {
                            message: msg,
                            code: None,
                            source: Some(Box::new(e)),
                        });
                    }
                };

                if input_passphrase != confirm_passphrase {
                    input_passphrase.zeroize();
                    confirm_passphrase.zeroize();
                    println!("{}", "❌ Passphrases do not match. Please try again.".red());
                    continue;
                }

                confirm_passphrase.zeroize();
                break input_passphrase;
            }
        };

        // Use official wallets directory only.
        let directory = DirectoryDB::from_node_opts(opts).map_err(|e| {
            let msg = format!("Failed to initialize directories: {}", e);
            json_logger
                .log_error_event("wallet", "GenerateWalletInitDirectoriesFailed", &msg)
                .ok();
            ErrorDetection::IoError {
                message: msg,
                code: None,
                source: None,
            }
        })?;

        directory.create_wallets_directory().map_err(|e| {
            let msg = format!("Failed to create/check wallets directory: {}", e);
            json_logger
                .log_error_event("wallet", "GenerateWalletCreateWalletDirFailed", &msg)
                .ok();
            ErrorDetection::IoError {
                message: msg,
                code: None,
                source: None,
            }
        })?;

        let wallet_path = &directory.wallets_path;

        println!("{}", "🔹 Generating your wallet...".cyan());

        for _ in 0..batch_count {
            let new_wallet = MLDSA65Wallet::new(&passphrase).map_err(|e| {
                passphrase.zeroize();
                let msg = format!("Failed to generate wallet: {e}");
                json_logger
                    .log_error_event("wallet", "GenerateWalletCreateFailed", &msg)
                    .ok();
                ErrorDetection::InitializationError { message: msg }
            })?;

            // Wipe passphrase ASAP on success path (single-wallet)
            if batch_count == 1 {
                passphrase.zeroize();
            }

            // Canonical invariant check: address format + matches public key.
            if let Err(e) = new_wallet.validate_self() {
                passphrase.zeroize();
                let msg = format!("Generated invalid wallet (self-validate failed): {e}");
                json_logger
                    .log_error_event("wallet", "GenerateWalletInvariantViolation", &msg)
                    .ok();
                return Err(ErrorDetection::ValidationError {
                    message: msg,
                    tx_id: None,
                });
            }

            println!(
                "{} {}",
                "✅ Wallet generated. Address:".green(),
                new_wallet.address
            );

            // Atomic write: tmp -> rename; refuse overwrite
            let wallet_file = wallet_path.join(format!("{}.wallet", new_wallet.address));
            if wallet_file.exists() {
                passphrase.zeroize();
                let msg = format!(
                    "Refusing to overwrite existing wallet file: {}",
                    wallet_file.display()
                );
                json_logger
                    .log_error_event("wallet", "GenerateWalletFileAlreadyExists", &msg)
                    .ok();
                return Err(ErrorDetection::ValidationError {
                    message: msg,
                    tx_id: None,
                });
            }

            let tmp_file = wallet_path.join(format!("{}.wallet.tmp", new_wallet.address));

            if let Err(e) = fs::remove_file(&tmp_file)
                && e.kind() != ErrorKind::NotFound
            {
                json_logger
                    .log_error_event(
                        "wallet",
                        "RemoveTempWalletFailed",
                        &format!("remove_file('{}') failed: {e}", tmp_file.display()),
                    )
                    .ok();
                // continue: we'll attempt to write tmp_file next
            }

            fs::write(&tmp_file, &new_wallet.encrypted_secret).map_err(|e| {
                passphrase.zeroize();
                let msg = format!("❌ Failed to save temp wallet file: {}", tmp_file.display());
                json_logger
                    .log_error_event("wallet", "GenerateWalletSaveTempFailed", &msg)
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
                if let Err(e) = fs::set_permissions(&tmp_file, fs::Permissions::from_mode(0o600)) {
                    let msg = format!(
                        "Warning: failed to set wallet file permissions to 0600 ({}): {}",
                        tmp_file.display(),
                        e
                    );
                    json_logger
                        .log_error_event("wallet", "GenerateWalletSetWalletPermsFailed", &msg)
                        .ok();
                }
            }

            fs::rename(&tmp_file, &wallet_file).map_err(|e| {
                passphrase.zeroize();
                let msg = format!(
                    "❌ Failed to finalize wallet file (rename {} -> {}): {}",
                    tmp_file.display(),
                    wallet_file.display(),
                    e
                );
                json_logger
                    .log_error_event("wallet", "GenerateWalletFinalizeRenameFailed", &msg)
                    .ok();
                ErrorDetection::IoError {
                    message: msg,
                    code: e.raw_os_error(),
                    source: Some(Box::new(e)),
                }
            })?;

            println!(
                "{}",
                format!("🔐 Wallet file saved at: {}", wallet_file.display()).green()
            );
            println!("{}", "✅ Wallet metadata stored in DB.".green());
        }

        if batch_count > 1 {
            println!(
                "{}",
                format!("🎉 Generated {} wallets.", batch_count).green()
            );
            passphrase.zeroize();
        }

        Ok(())
    }
}
