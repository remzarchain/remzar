//! src/commandline/s_05_send_remzar.rs
//! 05. Send Coins – write to mempool & broadcast (non-blocking CLI)

use crate::blockchain::transaction_001_tx::Transaction;
use crate::blockchain::transaction_004_tx_kind::TxKind;
use crate::blockchain::transaction_005_tx_account_tree::AccountModelTree;
use crate::cryptography::ml_dsa_65_005_encryption::Cryption;
use crate::network::p2p_010_netcmd::NetCmd;
use crate::privacy::privacy_001_private_receive_wallet::MAX_PRIVATE_RECEIVE_INVOICE_LEN;
use crate::privacy::privacy_002_private_receive_invoice::{PrivateRI, PrivateReceiveInvoiceSource};
use crate::runtime::p2p_006_sync_runtime::NodeOpts;
use crate::storage::rocksdb_000_directory::DirectoryDB;
use crate::storage::rocksdb_005_manager::RockDBManager;
use crate::utility::alpha_001_global_configuration::GlobalConfiguration;
use crate::utility::alpha_002_error_detection_system::ErrorDetection;
use crate::utility::hash_system_remzarhash::RemzarHash;
use crate::utility::helper::{
    canon_wallet_id_checked, derive_wallet_id_from_pubkey_bytes, from_micro_units,
    to_micro_units_str,
};
use crate::utility::logging_data::JsonLogger;
use crate::utility::time_policy::TimePolicy;

use colored::Colorize;
use dialoguer::Password;
use rust_rocksdb::WriteBatch;
use std::fs;
use std::io::{self, Write};
use std::sync::Arc;
use tokio::sync::mpsc::Sender;
use zeroize::Zeroize;

pub struct S05SendRemzar<'a> {
    db_manager: Arc<RockDBManager>,
    chain: &'a mut Option<AccountModelTree>,
    net_tx: Option<Sender<NetCmd>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SendRecipientMode {
    PublicSingle,
    PublicBatch,
    PrivateReceiveSingle,
}

impl SendRecipientMode {
    fn is_private_receive(self) -> bool {
        matches!(self, Self::PrivateReceiveSingle)
    }

    fn label(self) -> &'static str {
        match self {
            Self::PublicSingle => "public single recipient",
            Self::PublicBatch => "public batch recipients",
            Self::PrivateReceiveSingle => "private receive address",
        }
    }
}

impl<'a> S05SendRemzar<'a> {
    pub fn new(
        db_manager: Arc<RockDBManager>,
        chain: &'a mut Option<AccountModelTree>,
        net_tx: Option<Sender<NetCmd>>,
    ) -> Self {
        Self {
            db_manager,
            chain,
            net_tx,
        }
    }

    fn send_net_cmd(&self, cmd: NetCmd) -> Result<(), ErrorDetection> {
        let tx = self
            .net_tx
            .as_ref()
            .ok_or_else(|| ErrorDetection::ProtocolError {
                message: "Network thread not running".into(),
            })?;

        tx.try_send(cmd).map_err(|e| match e {
            tokio::sync::mpsc::error::TrySendError::Full(_) => ErrorDetection::ProtocolError {
                message: "Too many pending broadcasts; please wait".into(),
            },
            tokio::sync::mpsc::error::TrySendError::Closed(_) => ErrorDetection::ProtocolError {
                message: "Network thread has shut down".into(),
            },
        })
    }

    fn flush_stdout(json_logger: &JsonLogger, code: &str) -> Result<(), ErrorDetection> {
        io::stdout().flush().map_err(|e| {
            let msg = format!("Failed to flush stdout: {}", e);
            json_logger.log_error_event("tx", code, &msg).ok();
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
        Self::flush_stdout(json_logger, "SendRemzarFlushStdoutFailed")?;

        let mut s = String::new();
        io::stdin().read_line(&mut s).map_err(|e| {
            let msg = format!("Failed to read input: {}", e);
            json_logger.log_error_event("tx", log_code, &msg).ok();
            ErrorDetection::IoError {
                message: msg,
                code: e.raw_os_error(),
                source: Some(Box::new(e)),
            }
        })?;

        if s.len() > cap {
            let msg = format!("Input too long (max {} chars)", cap);
            json_logger
                .log_error_event("tx", "SendRemzarInputTooLong", &msg)
                .ok();
            return Err(ErrorDetection::ValidationError {
                message: msg,
                tx_id: None,
            });
        }

        Ok(s.trim().to_string())
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

    fn read_wallet_address(
        prompt: &str,
        json_logger: &JsonLogger,
        log_code: &str,
    ) -> Result<String, ErrorDetection> {
        let raw = Self::read_line_capped(prompt, 256, json_logger, log_code)?;
        canon_wallet_id_checked(&raw).map_err(|e| {
            let msg = format!("Invalid wallet address: {}", e);
            json_logger.log_error_event("tx", log_code, &msg).ok();
            ErrorDetection::ValidationError {
                message: msg,
                tx_id: None,
            }
        })
    }

    fn read_amount_micro(
        prompt: &str,
        json_logger: &JsonLogger,
        log_code: &str,
    ) -> Result<u64, ErrorDetection> {
        let amount_s = Self::read_line_capped(prompt, 256, json_logger, log_code)?;
        let normalized = amount_s.trim().replace(',', ".");
        let amount_u = to_micro_units_str(&normalized);

        if amount_u == 0 {
            let msg = "Invalid amount. Must be > 0 and have at most 8 decimals.";
            json_logger.log_error_event("tx", log_code, msg).ok();
            return Err(ErrorDetection::ValidationError {
                message: msg.into(),
                tx_id: None,
            });
        }

        Ok(amount_u)
    }

    fn make_ts_key() -> Result<String, ErrorDetection> {
        use rand::RngExt as _;

        // Runtime-only CLI/mempool storage key.
        let now_millis = TimePolicy::now_unix_millis_runtime()?;

        let now_microsish =
            now_millis
                .checked_mul(1_000)
                .ok_or_else(|| ErrorDetection::TimestampError {
                    message: "Failed to generate timestamp key".into(),
                    details: "milliseconds-to-microseconds multiplication overflowed".into(),
                    source: None,
                })?;

        let rnd: u32 = rand::rng().random();

        Ok(format!("tx_{}_{}", now_microsish, rnd))
    }

    fn read_private_receive_target(
        sender: &str,
        json_logger: &JsonLogger,
    ) -> Result<(String, String, PrivateReceiveInvoiceSource), ErrorDetection> {
        loop {
            let raw = match Self::read_line_capped(
                "Enter recipient private receive invoice/address: ",
                MAX_PRIVATE_RECEIVE_INVOICE_LEN,
                json_logger,
                "SendRemzarPrivateReceiveInvoiceReadFailed",
            ) {
                Ok(v) => v,
                Err(e) => {
                    println!("{}", format!("❌ {}", e).red());
                    continue;
                }
            };

            let parsed = match PrivateRI::parse_invoice_or_address(&raw) {
                Ok(v) => v,
                Err(e) => {
                    let msg = format!("Invalid private receive invoice/address: {e}");
                    json_logger
                        .log_error_event("tx", "SendRemzarPrivateReceiveInvoiceInvalid", &msg)
                        .ok();

                    println!("{}", format!("❌ {}", msg).red());
                    println!(
                        "{}",
                        "Expected format: remzar-private-receive:v1:<one-time-wallet>".yellow()
                    );
                    continue;
                }
            };

            if parsed.one_time_wallet == sender {
                let msg = "You cannot send coins to yourself, even through private receive mode.";
                json_logger
                    .log_error_event("tx", "SendRemzarPrivateReceiveSelfSend", msg)
                    .ok();

                println!("{}", format!("❌ {}", msg).red());
                continue;
            }

            let preview = match PrivateRI::display_preview(&parsed.canonical_invoice) {
                Ok(v) => v,
                Err(e) => {
                    json_logger
                        .log_error_event(
                            "tx",
                            "SendRemzarPrivateReceivePreviewFailed",
                            &format!("{e:?}"),
                        )
                        .ok();

                    "<preview unavailable>".to_string()
                }
            };

            return Ok((parsed.one_time_wallet, preview, parsed.source));
        }
    }

    pub fn send_remzar(
        &mut self,
        opts: &NodeOpts,
        json_logger: &JsonLogger,
    ) -> Result<(), ErrorDetection> {
        const MAX_YN_INPUT_LEN: usize = 16;
        const MAX_MODE_INPUT_LEN: usize = 16;
        const MAX_BATCH_INPUT_LEN: usize = 16;
        const MAX_BATCH_RECIPIENTS: usize = 10;

        // 1) Prompt to proceed
        let proceed = loop {
            match Self::read_yes_no(
                &format!("{}", "💰 Do you want to send coins? (yes/no): ".yellow()),
                MAX_YN_INPUT_LEN,
                json_logger,
                "SendRemzarReadConfirmInputFailed",
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

        // 2) Gather & validate sender
        let sender = Self::read_wallet_address(
            "Enter your wallet address (sender): ",
            json_logger,
            "SendRemzarReadSenderFailed",
        )?;

        // 3) Passphrase entry
        let mut passphrase = Password::new()
            .with_prompt("🔒 Enter passphrase for this wallet")
            .allow_empty_password(false)
            .interact()
            .map_err(|e| ErrorDetection::IoError {
                message: format!("Failed to read passphrase: {e}"),
                code: None,
                source: Some(Box::new(e)),
            })?;

        let mut confirm_passphrase = Password::new()
            .with_prompt("🔒 Confirm your passphrase")
            .allow_empty_password(false)
            .interact()
            .map_err(|e| ErrorDetection::IoError {
                message: format!("Failed to read passphrase confirmation: {e}"),
                code: None,
                source: Some(Box::new(e)),
            })?;

        if passphrase != confirm_passphrase {
            passphrase.zeroize();
            confirm_passphrase.zeroize();

            let msg = "Passphrase confirmation does not match.";
            json_logger
                .log_error_event("tx", "SendRemzarPassphraseMismatch", msg)
                .ok();

            return Err(ErrorDetection::ValidationError {
                message: msg.into(),
                tx_id: None,
            });
        }
        confirm_passphrase.zeroize();

        // 4) Locate wallet file
        let directory = DirectoryDB::from_node_opts(opts).map_err(|e| {
            let msg = format!("Failed to initialise directories: {e}");
            json_logger
                .log_error_event("tx", "SendRemzarInitDirectoriesFailed", &msg)
                .ok();
            ErrorDetection::StorageError { message: msg }
        })?;

        let wallet_file = directory.wallets_path.join(format!("{}.wallet", sender));
        if !wallet_file.exists() {
            passphrase.zeroize();
            let msg = format!("Wallet file not found at {}", wallet_file.display());
            json_logger
                .log_error_event("tx", "SendRemzarWalletFileMissing", &msg)
                .ok();
            return Err(ErrorDetection::NotFound { resource: msg });
        }

        let mut encrypted_secret = fs::read(&wallet_file).map_err(|e| {
            passphrase.zeroize();
            let msg = format!("Failed to read wallet file: {e}");
            json_logger
                .log_error_event("tx", "SendRemzarReadWalletFileFailed", &msg)
                .ok();
            ErrorDetection::IoError {
                message: msg,
                code: e.raw_os_error(),
                source: Some(Box::new(e)),
            }
        })?;

        // 5) Decrypt wallet and verify sender binding
        {
            use fips204::ml_dsa_65;
            use fips204::traits::{SerDes, Signer};

            let mut decrypted = Cryption::decrypt_private_key_bytes(&encrypted_secret, &passphrase)
                .map_err(|e| {
                    let msg = format!("Wallet decryption failed: {e}");
                    json_logger
                        .log_error_event("tx", "SendRemzarDecryptWalletFailed", &msg)
                        .ok();
                    ErrorDetection::DecryptionError { message: msg }
                })?;

            let mut sk_raw: Vec<u8> = if decrypted.len() == ml_dsa_65::SK_LEN {
                decrypted
            } else if decrypted.len() == Cryption::ML_DSA_65_SECRET_HEX_CHARS {
                let hex_str = match std::str::from_utf8(&decrypted) {
                    Ok(s) => s,
                    Err(e) => {
                        decrypted.zeroize();
                        passphrase.zeroize();
                        encrypted_secret.zeroize();

                        let msg = format!("Wallet payload is not valid UTF-8 hex: {e}");
                        json_logger
                            .log_error_event("tx", "SendRemzarWalletPayloadInvalidUtf8", &msg)
                            .ok();
                        return Err(ErrorDetection::ValidationError {
                            message: msg,
                            tx_id: None,
                        });
                    }
                };

                let mut raw = match hex::decode(hex_str) {
                    Ok(v) => v,
                    Err(e) => {
                        decrypted.zeroize();
                        passphrase.zeroize();
                        encrypted_secret.zeroize();

                        let msg = format!("Wallet payload hex decode failed: {e}");
                        json_logger
                            .log_error_event("tx", "SendRemzarWalletHexDecodeFailed", &msg)
                            .ok();
                        return Err(ErrorDetection::ValidationError {
                            message: msg,
                            tx_id: None,
                        });
                    }
                };

                decrypted.zeroize();

                if raw.len() != ml_dsa_65::SK_LEN {
                    raw.zeroize();
                    passphrase.zeroize();
                    encrypted_secret.zeroize();

                    let msg = format!(
                        "Decoded wallet secret length mismatch: expected {} bytes, got {}",
                        ml_dsa_65::SK_LEN,
                        raw.len()
                    );
                    json_logger
                        .log_error_event("tx", "SendRemzarWalletLengthMismatch", &msg)
                        .ok();
                    return Err(ErrorDetection::ValidationError {
                        message: msg,
                        tx_id: None,
                    });
                }

                raw
            } else {
                let got = decrypted.len();
                decrypted.zeroize();
                passphrase.zeroize();
                encrypted_secret.zeroize();

                let msg = format!(
                    "Wallet payload length unsupported: expected {} (raw) or {} (hex), got {}",
                    ml_dsa_65::SK_LEN,
                    Cryption::ML_DSA_65_SECRET_HEX_CHARS,
                    got
                );
                json_logger
                    .log_error_event("tx", "SendRemzarWalletLengthUnsupported", &msg)
                    .ok();
                return Err(ErrorDetection::ValidationError {
                    message: msg,
                    tx_id: None,
                });
            };

            let sk_arr: [u8; ml_dsa_65::SK_LEN] = match sk_raw.as_slice().try_into() {
                Ok(a) => a,
                Err(_) => {
                    sk_raw.zeroize();
                    passphrase.zeroize();
                    encrypted_secret.zeroize();

                    let msg = "Failed to convert wallet secret into fixed-size ML-DSA-65 array."
                        .to_string();
                    json_logger
                        .log_error_event("tx", "SendRemzarWalletArrayConvertFailed", &msg)
                        .ok();
                    return Err(ErrorDetection::ValidationError {
                        message: msg,
                        tx_id: None,
                    });
                }
            };

            sk_raw.zeroize();

            let sk = ml_dsa_65::PrivateKey::try_from_bytes(sk_arr).map_err(|e| {
                let msg = format!("Invalid ML-DSA-65 secret key bytes: {e}");
                json_logger
                    .log_error_event("tx", "SendRemzarWalletKeyReconstructFailed", &msg)
                    .ok();
                ErrorDetection::CryptographicError { message: msg }
            })?;

            let pk = sk.get_public_key();
            let pk_bytes = pk.into_bytes();

            let derived = derive_wallet_id_from_pubkey_bytes(&pk_bytes);

            if derived != sender {
                passphrase.zeroize();
                encrypted_secret.zeroize();

                let msg = format!(
                    "Unlocked key does not match sender wallet.\n- sender: {}\n- derived: {}",
                    sender, derived
                );
                json_logger
                    .log_error_event("tx", "SendRemzarWalletAddressMismatch", &msg)
                    .ok();
                return Err(ErrorDetection::ValidationError {
                    message: msg,
                    tx_id: None,
                });
            }
        }

        passphrase.zeroize();
        encrypted_secret.zeroize();

        // 6) Choose send mode
        let (
            recipients,
            amount_each,
            recipient_mode,
            private_receive_preview,
            private_receive_source,
        ): (
            Vec<String>,
            u64,
            SendRecipientMode,
            Option<String>,
            Option<PrivateReceiveInvoiceSource>,
        ) = loop {
            println!("{}", "🔹 Select Send Mode".cyan());
            println!("{}", "  [1] Send to Single Public Recipient".cyan());
            println!("{}", "  [2] Send to Private Receive Address".cyan());
            println!(
                "{}",
                "  [3] Send to Multiple Public Recipients (2-10)".cyan()
            );
            println!("{}", "  [4] Exit (Back to Menu)".cyan());

            let choice = match Self::read_line_capped(
                "Enter choice (1-4): ",
                MAX_MODE_INPUT_LEN,
                json_logger,
                "SendRemzarModeMenuReadFailed",
            ) {
                Ok(v) => v,
                Err(e) => {
                    println!("{}", format!("❌ {}", e).red());
                    continue;
                }
            };

            match choice.as_str() {
                "1" => {
                    let recipient = loop {
                        let r = match Self::read_wallet_address(
                            "Enter recipient's public address: ",
                            json_logger,
                            "SendRemzarRecipientReadFailed",
                        ) {
                            Ok(v) => v,
                            Err(e) => {
                                println!("{}", format!("❌ {}", e).red());
                                continue;
                            }
                        };

                        if r == sender {
                            println!("{}", "❌ You cannot send coins to yourself.".red());
                            continue;
                        }

                        break r;
                    };

                    let amount = loop {
                        match Self::read_amount_micro(
                            "Enter amount to send (in ZAR, e.g. 0.000001): ",
                            json_logger,
                            "SendRemzarAmountReadFailed",
                        ) {
                            Ok(v) => break v,
                            Err(e) => {
                                println!("{}", format!("❌ {}", e).red());
                                continue;
                            }
                        }
                    };

                    break (
                        vec![recipient],
                        amount,
                        SendRecipientMode::PublicSingle,
                        None,
                        None,
                    );
                }
                "2" => {
                    println!();
                    println!("{}", "🔹 Send to Private Receive Address".cyan());
                    println!(
                        "{}",
                        "Paste the recipient's private receive invoice.".yellow()
                    );
                    println!(
                        "{}",
                        "Privacy limit: sender, amount, and timestamp stay public. The recipient's MAIN wallet is hidden because this sends to a one-time wallet."
                            .yellow()
                    );

                    let (recipient, preview, source) =
                        Self::read_private_receive_target(&sender, json_logger)?;

                    let amount = loop {
                        match Self::read_amount_micro(
                            "Enter amount to send to this private receive address (in ZAR, e.g. 0.000001): ",
                            json_logger,
                            "SendRemzarPrivateReceiveAmountReadFailed",
                        ) {
                            Ok(v) => break v,
                            Err(e) => {
                                println!("{}", format!("❌ {}", e).red());
                                continue;
                            }
                        }
                    };

                    break (
                        vec![recipient],
                        amount,
                        SendRecipientMode::PrivateReceiveSingle,
                        Some(preview),
                        Some(source),
                    );
                }
                "3" => {
                    let n: usize = loop {
                        let v = match Self::read_line_capped(
                            "🔢 How many public recipients do you want to send to? (2-10): ",
                            MAX_BATCH_INPUT_LEN,
                            json_logger,
                            "SendRemzarBatchCountReadFailed",
                        ) {
                            Ok(v) => v,
                            Err(e) => {
                                println!("{}", format!("❌ {}", e).red());
                                continue;
                            }
                        };

                        match v.parse::<usize>() {
                            Ok(x) if (2..=MAX_BATCH_RECIPIENTS).contains(&x) => break x,
                            Ok(_) => {
                                println!("{}", "❌ Invalid number. Please choose 2 to 10.".red())
                            }
                            Err(_) => {
                                println!("{}", "❌ Invalid number. Please enter digits only.".red())
                            }
                        }
                    };

                    loop {
                        match Self::read_yes_no(
                            &format!(
                                "🔁 You will send to {} public recipients. Proceed? (yes/no): ",
                                n
                            ),
                            MAX_YN_INPUT_LEN,
                            json_logger,
                            "SendRemzarBatchConfirmReadFailed",
                        ) {
                            Ok(true) => break,
                            Ok(false) => return Ok(()),
                            Err(ErrorDetection::ValidationError { message, .. }) => {
                                println!("{}", format!("❌ {}", message).red())
                            }
                            Err(e) => return Err(e),
                        }
                    }

                    let mut recips: Vec<String> = Vec::with_capacity(n);
                    for i in 1..=n {
                        loop {
                            let r = match Self::read_wallet_address(
                                &format!("Enter recipient #{} public address: ", i),
                                json_logger,
                                "SendRemzarRecipientReadFailed",
                            ) {
                                Ok(v) => v,
                                Err(e) => {
                                    println!("{}", format!("❌ {}", e).red());
                                    continue;
                                }
                            };

                            if r == sender {
                                println!("{}", "❌ You cannot send coins to yourself.".red());
                                continue;
                            }

                            if recips.iter().any(|x| x == &r) {
                                println!(
                                    "{}",
                                    "❌ Duplicate recipient address. Please enter a unique address."
                                        .red()
                                );
                                continue;
                            }

                            recips.push(r);
                            break;
                        }
                    }

                    let amount = loop {
                        match Self::read_amount_micro(
                            "Enter amount to send to EACH public recipient (in ZAR, e.g. 0.000001): ",
                            json_logger,
                            "SendRemzarAmountReadFailed",
                        ) {
                            Ok(v) => break v,
                            Err(e) => {
                                println!("{}", format!("❌ {}", e).red());
                                continue;
                            }
                        }
                    };

                    break (recips, amount, SendRecipientMode::PublicBatch, None, None);
                }
                "4" => return Ok(()),
                _ => {
                    println!(
                        "{}",
                        "❌ Invalid choice. Please choose 1, 2, 3, or 4.".red()
                    );
                    continue;
                }
            }
        };

        let total_amount = amount_each.saturating_mul(recipients.len() as u64);
        if total_amount == 0 {
            return Err(ErrorDetection::ValidationError {
                message: "Invalid total amount. Must be > 0.".into(),
                tx_id: None,
            });
        }

        // 7) Balance checks
        let cached_balance = match self
            .db_manager
            .read(GlobalConfiguration::ACCOUNT_COLUMN_NAME, sender.as_bytes())
        {
            Ok(Some(bytes)) => postcard::from_bytes::<u64>(&bytes).unwrap_or(0),
            _ => 0,
        };

        let balance = match self.db_manager.load_state() {
            Ok(state_tree) => state_tree.get_balance(&sender),
            Err(e) => {
                let msg = format!("Failed to load canonical account state snapshot: {:?}", e);
                json_logger
                    .log_error_event("tx", "SendRemzarLoadAccountStateFailed", &msg)
                    .ok();

                if let Some(chain) = self.chain.as_mut() {
                    chain.reload_from_db();
                    chain.get_balance(&sender)
                } else {
                    0
                }
            }
        };

        if cached_balance != balance {
            let msg = format!(
                "ACCOUNT cache mismatch for {}: cached={} canonical={}",
                sender, cached_balance, balance
            );
            json_logger
                .log_error_event("tx", "SendRemzarAccountCacheMismatch", &msg)
                .ok();

            if let Ok(buf) = postcard::to_allocvec(&balance) {
                _ = self.db_manager.write(
                    GlobalConfiguration::ACCOUNT_COLUMN_NAME,
                    sender.as_bytes(),
                    &buf,
                );
            }
        }

        if total_amount > balance {
            println!(
                "❌ Insufficient balance! You need {:.8} ZAR but only have {:.8} ZAR.",
                from_micro_units(total_amount),
                from_micro_units(balance)
            );
            return Ok(());
        }

        // 8) Final confirmation preview
        match recipient_mode {
            SendRecipientMode::PublicSingle => {
                let only = recipients
                    .first()
                    .ok_or_else(|| ErrorDetection::ValidationError {
                        message: "Public single send mode requires exactly one recipient".into(),
                        tx_id: None,
                    })?;

                println!(
                    "\nYou are about to send {:.8} ZAR from:\n  {}\nto public recipient:\n  {}\n",
                    from_micro_units(total_amount),
                    sender.green(),
                    only.green(),
                );
            }
            SendRecipientMode::PrivateReceiveSingle => {
                let only = recipients
                    .first()
                    .ok_or_else(|| ErrorDetection::ValidationError {
                        message: "Private receive send mode requires exactly one recipient".into(),
                        tx_id: None,
                    })?;

                let source_label = match private_receive_source {
                    Some(PrivateReceiveInvoiceSource::Invoice) => "private receive invoice",
                    Some(PrivateReceiveInvoiceSource::RawOneTimeWallet) => "raw one-time wallet",
                    None => "private receive target",
                };

                println!(
                    "\nYou are about to send {:.8} ZAR from:\n  {}\nto PRIVATE RECEIVE one-time wallet:\n  {}\n",
                    from_micro_units(total_amount),
                    sender.green(),
                    only.green(),
                );

                if let Some(preview) = private_receive_preview.as_deref() {
                    println!("Invoice preview: {}", preview.green());
                }

                println!("Input type: {}", source_label.yellow());
                println!(
                    "{}",
                    "Reminder: this is a normal on-chain transfer to a one-time wallet. Sender, amount, and timestamp remain public; recipient's main wallet is not shown."
                        .yellow()
                );
                println!();
            }
            SendRecipientMode::PublicBatch => {
                println!(
                    "\nYou are about to send {:.8} ZAR TOTAL from:\n  {}\nAmount per public recipient: {:.8}\nRecipients ({}):",
                    from_micro_units(total_amount),
                    sender.green(),
                    from_micro_units(amount_each),
                    recipients.len()
                );
                for r in &recipients {
                    println!("  {}", r.green());
                }
                println!();
            }
        }

        let confirmed = loop {
            match Self::read_yes_no(
                "Do you want to proceed? (yes/no): ",
                MAX_YN_INPUT_LEN,
                json_logger,
                "SendRemzarFinalConfirmReadFailed",
            ) {
                Ok(v) => break v,
                Err(ErrorDetection::ValidationError { message, .. }) => {
                    println!("{}", format!("❌ {}", message).red())
                }
                Err(e) => return Err(e),
            }
        };

        if !confirmed {
            println!("{}", "❌ Transaction cancelled by user.".red());
            return Ok(());
        }

        // 9) Re-check balance just before queueing
        let balance_now = match self.db_manager.load_state() {
            Ok(state_tree) => state_tree.get_balance(&sender),
            Err(_) => {
                if let Some(chain) = self.chain.as_mut() {
                    chain.reload_from_db();
                    chain.get_balance(&sender)
                } else {
                    balance
                }
            }
        };

        if total_amount > balance_now {
            println!(
                "❌ Balance changed before send. Need {:.8} ZAR but now have {:.8} ZAR.",
                from_micro_units(total_amount),
                from_micro_units(balance_now)
            );
            return Ok(());
        }

        // 10) Open DB + CFs
        let db = self.db_manager.open_db_blockchain().map_err(|e| {
            let msg = format!("Failed to open blockchain DB: {}", e);
            json_logger
                .log_error_event("tx", "SendRemzarOpenDbFailed", &msg)
                .ok();
            ErrorDetection::DatabaseError { details: msg }
        })?;

        let cf_tx = db
            .cf_handle(GlobalConfiguration::TRANSACTION_COLUMN_NAME)
            .ok_or_else(|| {
                let msg = format!(
                    "{} CF missing",
                    GlobalConfiguration::TRANSACTION_COLUMN_NAME
                );
                json_logger
                    .log_error_event("tx", "SendRemzarCfMissingTx", &msg)
                    .ok();
                ErrorDetection::DatabaseError { details: msg }
            })?;

        let cf_hash = db
            .cf_handle(GlobalConfiguration::TX_TO_HASH_COLUMN_NAME)
            .ok_or_else(|| {
                let msg = format!("{} CF missing", GlobalConfiguration::TX_TO_HASH_COLUMN_NAME);
                json_logger
                    .log_error_event("tx", "SendRemzarCfMissingHash", &msg)
                    .ok();
                ErrorDetection::DatabaseError { details: msg }
            })?;

        // 11) Queue each tx
        let mut queued = 0usize;

        for recipient in &recipients {
            let tx = Transaction::new(sender.clone(), recipient.clone(), amount_each)?;

            let tx_kind = TxKind::Transfer(tx.clone());
            let tx_bytes = postcard::to_allocvec(&tx_kind).map_err(|e| {
                let msg = format!("TxKind serialize failed: {e}");
                json_logger
                    .log_error_event("tx", "SendRemzarSerializeTxFailed", &msg)
                    .ok();
                ErrorDetection::SerializationError { details: msg }
            })?;

            let hash = RemzarHash::compute_bytes_hash(&tx_bytes);

            if db
                .get_pinned_cf(&cf_hash, hash.as_slice())
                .map_err(|e| ErrorDetection::StorageError {
                    message: format!("Failed to check existing tx hash: {}", e),
                })?
                .is_none()
            {
                let ts_key = Self::make_ts_key()?;

                let mut wb = WriteBatch::default();
                wb.put_cf(&cf_tx, ts_key.as_bytes(), &tx_bytes);
                wb.put_cf(&cf_hash, hash.as_slice(), &tx_bytes);

                db.write_opt(&wb, &RockDBManager::sync_write_options())
                    .map_err(|e| {
                        let msg = format!("Failed adding tx to mempool: {}", e);
                        json_logger
                            .log_error_event("tx", "SendRemzarWriteMempoolFailed", &msg)
                            .ok();
                        ErrorDetection::StorageError { message: msg }
                    })?;
            } else {
                let msg = format!("Duplicate tx hash detected for {}", recipient);
                json_logger
                    .log_error_event("tx", "SendRemzarDuplicateTxHash", &msg)
                    .ok();
            }

            self.send_net_cmd(NetCmd::SendTx(tx)).map_err(|e| {
                let msg = format!("Failed to queue TX broadcast: {}", e);
                json_logger
                    .log_error_event("tx", "SendRemzarBroadcastQueueFailed", &msg)
                    .ok();
                e
            })?;

            queued = queued.saturating_add(1);

            if recipient_mode.is_private_receive() {
                println!(
                    "✅ Private receive transfer queued & broadcast: {:.8} ZAR from {} to one-time wallet {}",
                    from_micro_units(amount_each),
                    sender.green(),
                    recipient.green()
                );
            } else {
                println!(
                    "✅ Transaction queued & broadcast: {:.8} ZAR from {} to {}",
                    from_micro_units(amount_each),
                    sender.green(),
                    recipient.green()
                );
            }
        }

        if recipients.len() > 1 {
            println!(
                "{}",
                format!(
                    "🎉 Batch send complete. {} transactions queued as {}.",
                    queued,
                    recipient_mode.label()
                )
                .green()
            );
        }

        Ok(())
    }
}
