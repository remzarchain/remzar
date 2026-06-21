//! src/commandline/s_06_receive_remzar.rs
//! 06. Receive Coins — read-only “live” watcher for incoming transactions

use crate::blockchain::transaction_001_tx::Transaction;
use crate::blockchain::transaction_004_tx_kind::TxKind;
use crate::blockchain::transaction_004_tx_kind::normalize_address_bytes;
use crate::runtime::p2p_006_sync_runtime::NodeOpts;
use crate::storage::rocksdb_000_directory::DirectoryDB;
use crate::storage::rocksdb_001_cf_descriptors::CFDescriptors;
use crate::utility::alpha_001_global_configuration::GlobalConfiguration;
use crate::utility::alpha_002_error_detection_system::ErrorDetection;
use crate::utility::hash_system_remzarhash::RemzarHash;
use crate::utility::helper::{canon_wallet_id_checked, from_micro_units};
use crate::utility::logging_data::JsonLogger;

use colored::Colorize;
use rust_rocksdb::{ColumnFamilyDescriptor, DB, IteratorMode, Options};
use std::collections::HashSet;
use std::io::{self, Write};
use std::thread::sleep;
use std::time::Duration;

#[derive(Default)]
pub struct S06ReceiveRemzar;

impl S06ReceiveRemzar {
    pub fn new() -> Self {
        Self
    }

    fn flush_stdout(json_logger: &JsonLogger, code: &str) -> Result<(), ErrorDetection> {
        io::stdout().flush().map_err(|e| {
            let msg = format!("Failed to flush stdout: {}", e);
            json_logger.log_error_event("rx", code, &msg).ok();
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
        Self::flush_stdout(json_logger, "ReceiveRemzarFlushStdoutFailed")?;

        let mut s = String::new();
        io::stdin().read_line(&mut s).map_err(|e| {
            let msg = format!("Failed to read input: {}", e);
            json_logger.log_error_event("rx", log_code, &msg).ok();
            ErrorDetection::IoError {
                message: msg,
                code: e.raw_os_error(),
                source: Some(Box::new(e)),
            }
        })?;

        if s.len() > cap {
            let msg = format!("Input too long (max {} chars)", cap);
            json_logger
                .log_error_event("rx", "ReceiveRemzarInputTooLong", &msg)
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

    fn read_wallet_or_exit(
        prompt: &str,
        json_logger: &JsonLogger,
        log_code: &str,
    ) -> Result<Option<String>, ErrorDetection> {
        let raw = Self::read_line_capped(prompt, 256, json_logger, log_code)?;
        if raw.eq_ignore_ascii_case("exit") {
            return Ok(None);
        }

        let canon = canon_wallet_id_checked(&raw).map_err(|e| {
            let msg = format!("Invalid wallet address: {}", e);
            json_logger.log_error_event("rx", log_code, &msg).ok();
            ErrorDetection::ValidationError {
                message: msg,
                tx_id: None,
            }
        })?;

        Ok(Some(canon))
    }

    fn canonical_address_from_tx_bytes(
        addr_bytes: &[u8],
        json_logger: &JsonLogger,
        invalid_bytes_code: &str,
        noncanonical_code: &str,
        side_label: &str,
    ) -> Result<String, ErrorDetection> {
        let addr = normalize_address_bytes(addr_bytes);
        if addr.is_empty() {
            let msg = format!("Skipping tx: invalid {} wallet bytes", side_label);
            json_logger
                .log_error_event("rx", invalid_bytes_code, &msg)
                .ok();
            return Err(ErrorDetection::ValidationError {
                message: msg,
                tx_id: None,
            });
        }

        canon_wallet_id_checked(&addr).map_err(|e| {
            let msg = format!("Skipping tx: non-canonical {} wallet: {}", side_label, e);
            json_logger
                .log_error_event("rx", noncanonical_code, &msg)
                .ok();
            ErrorDetection::ValidationError {
                message: msg,
                tx_id: None,
            }
        })
    }

    pub fn receive_remzar(
        &mut self,
        opts: &NodeOpts,
        json_logger: &JsonLogger,
    ) -> Result<(), ErrorDetection> {
        const MAX_YN_INPUT_LEN: usize = 16;

        let proceed = loop {
            match Self::read_yes_no(
                &format!(
                    "{}",
                    "📥 Do you want to see incoming coins? (yes/no): ".yellow()
                ),
                MAX_YN_INPUT_LEN,
                json_logger,
                "ReceiveRemzarReadConfirmInputFailed",
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

        let directory = DirectoryDB::from_node_opts(opts).map_err(|e| {
            let msg = format!("Failed to initialize directories: {}", e);
            json_logger
                .log_error_event("rx", "ReceiveRemzarDirectoryDBInitFailed", &msg)
                .ok();
            ErrorDetection::StorageError { message: msg }
        })?;
        let blockchain_path = &directory.blockchain_path;

        let cf_descriptors = CFDescriptors::get_cf_descriptors();

        let wallet_norm = loop {
            match Self::read_wallet_or_exit(
                &format!(
                    "{}",
                    "Enter your wallet address (or type \"exit\" to return to menu): ".yellow()
                ),
                json_logger,
                "ReceiveRemzarWalletAddrReadFailed",
            ) {
                Ok(Some(wallet)) => break wallet,
                Ok(None) => {
                    println!("{}", "❌ Returning to the menu.".red());
                    return Ok(());
                }
                Err(ErrorDetection::ValidationError { message, .. }) => {
                    println!("{}", format!("❌ {}", message).red());
                    continue;
                }
                Err(e) => return Err(e),
            }
        };

        let mut attempt: u32 = 0;

        loop {
            attempt = attempt.saturating_add(1);

            let mut opts_db = Options::default();
            opts_db.create_if_missing(false);
            opts_db.create_missing_column_families(false);

            let cfs_clone: Vec<ColumnFamilyDescriptor> = cf_descriptors
                .iter()
                .map(CFDescriptors::clone_column_family_descriptor)
                .collect();

            let db_result =
                DB::open_cf_descriptors_read_only(&opts_db, blockchain_path, cfs_clone, false);

            match db_result {
                Err(e) => {
                    let msg_lc = e.to_string().to_lowercase();
                    if attempt < GlobalConfiguration::MAX_ATTEMPTS
                        && (msg_lc.contains("lock") || msg_lc.contains("busy"))
                    {
                        println!(
                            "🔄 Busy (attempt {}/{}). Retrying in {} s...",
                            attempt,
                            GlobalConfiguration::MAX_ATTEMPTS,
                            GlobalConfiguration::RETRY_DELAY_SECS
                        );
                        sleep(Duration::from_secs(GlobalConfiguration::RETRY_DELAY_SECS));
                        continue;
                    }

                    let msg = format!("Failed to open DB after {} attempts: {}", attempt, e);
                    json_logger
                        .log_error_event("rx", "ReceiveRemzarOpenDbFailed", &msg)
                        .ok();
                    return Err(ErrorDetection::DatabaseError { details: msg });
                }
                Ok(db) => {
                    let cf = db
                        .cf_handle(GlobalConfiguration::TRANSACTION_COLUMN_NAME)
                        .ok_or_else(|| {
                            let msg = format!(
                                "Column family '{}' not found",
                                GlobalConfiguration::TRANSACTION_COLUMN_NAME
                            );
                            json_logger
                                .log_error_event("rx", "ReceiveRemzarCfMissingTx", &msg)
                                .ok();
                            ErrorDetection::DatabaseError { details: msg }
                        })?;

                    let mut incoming: Vec<(String, f64)> = Vec::new();
                    let mut seen: HashSet<[u8; 64]> = HashSet::new();

                    for entry in db.iterator_cf(&cf, IteratorMode::Start) {
                        let (_k, bytes) = entry.map_err(|e| {
                            let msg = format!("Error iterating mempool: {}", e);
                            json_logger
                                .log_error_event("rx", "ReceiveRemzarIterMempoolFailed", &msg)
                                .ok();
                            ErrorDetection::StorageError { message: msg }
                        })?;

                        let h: [u8; 64] = RemzarHash::compute_bytes_hash(&bytes);
                        if !seen.insert(h) {
                            continue;
                        }

                        let maybe_tx: Option<Transaction> =
                            match postcard::from_bytes::<TxKind>(&bytes) {
                                Ok(kind) => match kind {
                                    TxKind::Transfer(tx) => Some(tx),
                                    _ => None,
                                },
                                Err(_) => match Transaction::deserialize(&bytes) {
                                    Ok(tx) => Some(tx),
                                    Err(_) => {
                                        let msg =
                                            "Skipping mempool entry: decode failed".to_string();
                                        json_logger
                                            .log_error_event(
                                                "rx",
                                                "ReceiveRemzarSkipBadMempoolEntry",
                                                &msg,
                                            )
                                            .ok();
                                        continue;
                                    }
                                },
                            };

                        let tx = match maybe_tx {
                            Some(tx) => tx,
                            None => continue,
                        };

                        let recipient = match Self::canonical_address_from_tx_bytes(
                            &tx.receiver,
                            json_logger,
                            "ReceiveRemzarSkipBadRecipient",
                            "ReceiveRemzarSkipNonCanonicalRecipient",
                            "recipient",
                        ) {
                            Ok(v) => v,
                            Err(_) => continue,
                        };

                        if recipient != wallet_norm {
                            continue;
                        }

                        let sender = match Self::canonical_address_from_tx_bytes(
                            &tx.sender,
                            json_logger,
                            "ReceiveRemzarSkipBadSender",
                            "ReceiveRemzarSkipNonCanonicalSender",
                            "sender",
                        ) {
                            Ok(v) => v,
                            Err(_) => continue,
                        };

                        incoming.push((sender, from_micro_units(tx.amount)));
                    }

                    if incoming.is_empty() {
                        println!("{}", "No incoming transactions pending.".yellow());
                    } else {
                        println!("{}", "🔔 Incoming transactions pending:".cyan());
                        for (sender, amt) in incoming {
                            println!("  • {:.8} Remzar from {}", amt, sender.green());
                        }
                    }

                    return Ok(());
                }
            }
        }
    }
}
