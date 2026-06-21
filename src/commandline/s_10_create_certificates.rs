//! src/commandline/s_10_create_certificates.rs
//! 10. Create Certificate (hash, nft, documents, etc)
//!
//! This module isolates the certificate / NFT creation flow into its own
//! struct + impl, while keeping private CommandManager access inside the
//! manager wrapper.

use crate::blockchain::transaction_002_tx_register::RegisterNodeTx;
use crate::blockchain::transaction_004_tx_kind::TxKind;
use crate::cryptography::ml_dsa_65_005_encryption::Cryption;
use crate::cryptography::ml_dsa_65_006_edwallet::MLDSA65Wallet;
use crate::network::p2p_010_netcmd::NetCmd;
use crate::runtime::p2p_006_sync_runtime::NodeOpts;
use crate::storage::rocksdb_000_directory::DirectoryDB;
use crate::storage::rocksdb_005_manager::RockDBManager;
use crate::tokens::nft_001::{NftMintTx, NftTransferTx, load_nft_record};
use crate::tokens::rwa_asset_certificate::{
    RWA_ID_BYTES, RWA_KIND, RWA_SCHEMA, RwaAssetCertificate, RwaAssetClass, RwaAuditorVerification,
    RwaComplianceRules, RwaCoreFinancialData, RwaDocumentKind, RwaHash64, RwaLegalOwnershipData,
    RwaPayoutFrequency, RwaTechnicalBlockchainData, RwaTokenStandard,
    derive_certificate_id_from_entropy, document_from_bytes, to_pretty_json,
};
use crate::utility::alpha_001_global_configuration::GlobalConfiguration;
use crate::utility::alpha_002_error_detection_system::ErrorDetection;
use crate::utility::certificate_receipt::CertificateReceipt;
use crate::utility::digital_id_receipt::{DigitalPassport, DigitalPassportFields};
use crate::utility::hash_system_remzarhash::RemzarHash;
use crate::utility::logging_data::JsonLogger;
use crate::utility::time_policy::TimePolicy;
use chrono::DateTime;
use colored::Colorize;
use dialoguer::Password;
use fips204::ml_dsa_65;
use fips204::traits::{SerDes, Signer};
use pdf_writer::{Content, Name, Pdf, Rect, Ref, Str};
use rand::RngExt;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use zeroize::{Zeroize, Zeroizing};

const RWA_MAX_RETRIES: usize = 3;

pub struct S10CreateCertificates;

impl S10CreateCertificates {
    pub fn new() -> Self {
        Self
    }

    fn flush_stdout(stage: &'static str) -> Result<(), ErrorDetection> {
        io::stdout().flush().map_err(|e| ErrorDetection::IoError {
            message: format!("Failed to flush stdout ({stage}): {e}"),
            code: e.raw_os_error(),
            source: Some(Box::new(e)),
        })
    }

    fn read_line_capped(stage: &'static str, cap: usize) -> Result<String, ErrorDetection> {
        let mut s = String::new();
        io::stdin()
            .read_line(&mut s)
            .map_err(|e| ErrorDetection::IoError {
                message: format!("Failed to read input ({stage}): {e}"),
                code: e.raw_os_error(),
                source: Some(Box::new(e)),
            })?;

        if s.len() > cap {
            return Err(ErrorDetection::ValidationError {
                message: format!("Input too long ({stage}): max {} bytes", cap),
                tx_id: None,
            });
        }

        Ok(s)
    }

    fn confirm_yes_no(prompt: &str, stage: &'static str) -> Result<bool, ErrorDetection> {
        for _ in 0..GlobalConfiguration::MAX_ATTEMPTS {
            print!("{prompt}");
            Self::flush_stdout(stage)?;
            let line = Self::read_line_capped(stage, GlobalConfiguration::MAX_INPUT_BYTES)?;
            match line.trim().to_ascii_lowercase().as_str() {
                "yes" => return Ok(true),
                "no" => return Ok(false),
                _ => println!("{}", "❌ Please type 'yes' or 'no'.".red()),
            }
        }
        Ok(false)
    }

    fn canonicalize_wallet(addr: &str, label: &str) -> Result<String, ErrorDetection> {
        use crate::utility::helper::canon_wallet_id_checked;

        canon_wallet_id_checked(addr).map_err(|e| ErrorDetection::ValidationError {
            message: format!("{label} wallet address is invalid or incomplete: {e}"),
            tx_id: None,
        })
    }

    /// Runtime/off-chain UTC timestamp for certificate and Digital I.D. receipts.
    fn runtime_utc_timestamp() -> Result<String, ErrorDetection> {
        let now_unix = TimePolicy::now_unix_secs_runtime()?;

        let now_i64 = i64::try_from(now_unix).map_err(|_| ErrorDetection::TimestampError {
            message: "Timestamp error".into(),
            details: format!("runtime timestamp does not fit i64: {now_unix}"),
            source: None,
        })?;

        DateTime::from_timestamp(now_i64, 0)
            .map(|dt| dt.to_rfc3339())
            .ok_or_else(|| ErrorDetection::TimestampError {
                message: "Timestamp error".into(),
                details: format!("failed to format runtime timestamp as UTC: {now_unix}"),
                source: None,
            })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_certificates(
        &mut self,
        opts: &NodeOpts,
        db_manager: Arc<RockDBManager>,
        local_wallet: &str,
        audit_dir: &Path,
        pdf_dir: &Path,
        json_logger: &JsonLogger,
        send_net_cmd: &mut dyn FnMut(NetCmd) -> Result<(), ErrorDetection>,
    ) -> Result<(), ErrorDetection> {
        const NFT_ID_BYTES: usize = 64;
        const NFT_ID_HEX_LEN: usize = 128;
        const CONTENT_HASH_HEX_LEN: usize = 128;
        const MAX_CERT_FILE_BYTES: u64 = 2 * 1024 * 1024;

        println!();
        println!(
            "{}",
            "🔹 Certificate / NFT Creation (Mint NftMintTx)".cyan()
        );

        let confirmed = Self::confirm_yes_no(
            &format!(
                "{} ",
                "Do you want to create a new certificate / NFT? (yes/no):".yellow()
            ),
            "create_certificates.confirm",
        )?;
        if !confirmed {
            println!("{}", "❌ Creation cancelled, returning to menu.".red());
            return Ok(());
        }

        let (kind, schema) = loop {
            println!();
            println!("{}", "Select certificate / category type:".cyan());
            println!("  [1] Standard NFT (art / media / generic)");
            println!("  [2] Badge / Trophy (1-of-1 token)");
            println!("  [3] Legal document");
            println!("  [4] Certificate");
            println!("  [5] Software release");
            println!("  [6] Verify existing certificate / NFT");
            println!("  [7] Transfer certificate / NFT to another wallet");
            println!("  [8] Export certificate / NFT from chain");
            println!("  [9] Digital I.D");
            println!("  [10] RWA / Real-World Asset Certificate");
            println!("  [11] Cancel (return to main menu)");
            print!("Choice (1-11): ");
            Self::flush_stdout("create_certificates.kind.flush")?;

            let choice = Self::read_line_capped(
                "create_certificates.kind.read",
                GlobalConfiguration::MAX_INPUT_BYTES,
            )?;

            match choice.trim() {
                "1" => break ("Art".to_string(), "art-v1".to_string()),
                "2" => break ("Badge".to_string(), "badge-v1".to_string()),
                "3" => break ("LegalDocument".to_string(), "legal-v1".to_string()),
                "4" => break ("Certificate".to_string(), "certificate-v1".to_string()),
                "5" => break ("SoftwareRelease".to_string(), "release-v1".to_string()),
                "6" => {
                    self.verify_certificate_interactive(&db_manager, json_logger)?;
                    return Ok(());
                }
                "7" => {
                    self.transfer_certificate_interactive(
                        opts,
                        &db_manager,
                        audit_dir,
                        pdf_dir,
                        json_logger,
                        send_net_cmd,
                    )?;
                    return Ok(());
                }
                "8" => {
                    self.export_certificate_interactive(
                        &db_manager,
                        audit_dir,
                        pdf_dir,
                        json_logger,
                    )?;
                    return Ok(());
                }
                "9" => {
                    self.create_digital_id_interactive(
                        opts,
                        audit_dir,
                        pdf_dir,
                        json_logger,
                        send_net_cmd,
                    )?;
                    return Ok(());
                }
                "10" => {
                    self.create_rwa_certificate_interactive(
                        local_wallet,
                        audit_dir,
                        pdf_dir,
                        json_logger,
                        send_net_cmd,
                    )?;
                    return Ok(());
                }
                "11" => {
                    println!("{}", "↩️  Cancelled. Returning to menu.".yellow());
                    return Ok(());
                }
                _ => println!(
                    "{}",
                    "❌ Please type 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, or 11.".red()
                ),
            }
        };

        println!();
        println!(
            "{}",
            "Enter the path to the file (e.g. ./nfts/dog.png or ./docs/nda.pdf):".cyan()
        );
        print!("File path: ");
        Self::flush_stdout("create_certificates.filepath.flush")?;

        let file_path = Self::read_line_capped(
            "create_certificates.filepath.read",
            GlobalConfiguration::MAX_INPUT_BYTES,
        )?;
        let file_path = file_path.trim().to_string();

        if file_path.is_empty() {
            return Err(ErrorDetection::ValidationError {
                message: "File path cannot be empty".into(),
                tx_id: None,
            });
        }

        let meta = fs::metadata(&file_path).map_err(|e| ErrorDetection::IoError {
            message: format!("Failed to stat file {}: {e}", file_path),
            code: e.raw_os_error(),
            source: Some(Box::new(e)),
        })?;

        if !meta.is_file() {
            return Err(ErrorDetection::ValidationError {
                message: format!("Path is not a regular file: {}", file_path),
                tx_id: None,
            });
        }

        if meta.len() == 0 {
            return Err(ErrorDetection::ValidationError {
                message: "File is empty".into(),
                tx_id: None,
            });
        }

        if meta.len() > MAX_CERT_FILE_BYTES {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "File too large ({} bytes). Max allowed is {} bytes.",
                    meta.len(),
                    MAX_CERT_FILE_BYTES
                ),
                tx_id: None,
            });
        }

        let content_bytes = fs::read(&file_path).map_err(|e| ErrorDetection::IoError {
            message: format!("Failed to read file {}: {e}", file_path),
            code: e.raw_os_error(),
            source: Some(Box::new(e)),
        })?;

        let file_size = content_bytes.len();

        let file_name = Path::new(&file_path)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();

        println!();
        println!(
            "{}",
            "Enter a short title (e.g. 'Golden Dog #1' or 'NDA Alice/Bob')".cyan()
        );
        print!("Title: ");
        Self::flush_stdout("create_certificates.title.flush")?;

        let title = Self::read_line_capped(
            "create_certificates.title.read",
            GlobalConfiguration::MAX_INPUT_BYTES,
        )?;
        let title = title.trim().to_string();

        if title.is_empty() {
            return Err(ErrorDetection::ValidationError {
                message: "Title cannot be empty".into(),
                tx_id: None,
            });
        }

        println!();
        println!(
            "{}",
            "Enter owner wallet address (press Enter to use your local wallet):".cyan()
        );
        if !local_wallet.is_empty() {
            println!("(Default) {}", local_wallet.green());
        }

        print!("Owner wallet: ");
        Self::flush_stdout("create_certificates.owner.flush")?;

        let owner_wallet_in = Self::read_line_capped(
            "create_certificates.owner.read",
            GlobalConfiguration::MAX_INPUT_BYTES,
        )?;
        let owner_wallet_in = owner_wallet_in.trim().to_string();

        let owner_wallet = if owner_wallet_in.is_empty() {
            if local_wallet.is_empty() {
                return Err(ErrorDetection::ValidationError {
                    message: "No owner wallet provided and local wallet is empty".into(),
                    tx_id: None,
                });
            }
            Self::canonicalize_wallet(local_wallet, "Owner")?
        } else {
            Self::canonicalize_wallet(&owner_wallet_in, "Owner")?
        };

        if let Err(e) = RegisterNodeTx::new(owner_wallet.clone()) {
            let msg = format!("Owner wallet is not a valid Remzar address: {e:?}");
            json_logger
                .log_error_event("nft", "OwnerWalletInvalid", &msg)
                .ok();
            return Err(ErrorDetection::ValidationError {
                message: msg,
                tx_id: None,
            });
        }

        println!();
        println!(
            "{}",
            "Optional: enter picture size/resolution (e.g. 2.0MB or 1024x1024) or leave blank:"
                .cyan()
        );
        print!("Size: ");
        Self::flush_stdout("create_certificates.size.flush")?;
        let size_str = Self::read_line_capped(
            "create_certificates.size.read",
            GlobalConfiguration::MAX_INPUT_BYTES,
        )?;
        let size_str = size_str.trim().to_string();

        println!();
        println!(
            "{}",
            "Optional: extra description/note (collection name, doc type, version, etc.).".cyan()
        );
        print!("Description note: ");
        Self::flush_stdout("create_certificates.note.flush")?;
        let extra_note = Self::read_line_capped(
            "create_certificates.note.read",
            GlobalConfiguration::MAX_INPUT_BYTES,
        )?;
        let extra_note = extra_note.trim().to_string();

        println!();
        println!(
            "{}",
            "Optional: edition number (e.g. 01/01 for 1-of-1, or 01/100 for 1-of-100).".cyan()
        );
        print!("Edition: ");
        Self::flush_stdout("create_certificates.edition.flush")?;
        let edition_input = Self::read_line_capped(
            "create_certificates.edition.read",
            GlobalConfiguration::MAX_INPUT_BYTES,
        )?;
        let edition_input = edition_input.trim().to_string();

        let created_at = Self::runtime_utc_timestamp()?;

        let mut description_parts = Vec::new();
        description_parts.push(format!("Kind: {}", kind));
        description_parts.push(format!("Schema: {}", schema));
        description_parts.push(format!("File: {}", file_name));
        description_parts.push(format!("Size: {} bytes", file_size));
        if !size_str.is_empty() {
            description_parts.push(format!("Resolution: {}", size_str));
        }
        if !edition_input.is_empty() {
            description_parts.push(format!("Edition: {}", edition_input));
        }
        description_parts.push(format!("Minted at (UTC): {}", created_at));
        if !extra_note.is_empty() {
            description_parts.push(format!("Note: {}", extra_note));
        }
        description_parts.push(format!("Owner (requested): {}", owner_wallet));

        let description = description_parts.join(" | ");

        let mut nft_id = [0u8; NFT_ID_BYTES];
        rand::rng().fill(&mut nft_id);

        let nft_id_hex = hex::encode(nft_id);
        debug_assert_eq!(nft_id_hex.len(), NFT_ID_HEX_LEN);

        let tx = NftMintTx::from_content_bytes(
            nft_id,
            title.clone(),
            description.clone(),
            &content_bytes,
        );

        let content_hash_hex = hex::encode(tx.content_hash);
        debug_assert_eq!(content_hash_hex.len(), CONTENT_HASH_HEX_LEN);

        let local_expected = RemzarHash::compute_bytes_hash_hex(&content_bytes);
        if local_expected != content_hash_hex {
            let msg = format!(
                "Content hash mismatch: NftMintTx hash != RemzarHash hash (tx={}, local={})",
                content_hash_hex, local_expected
            );
            json_logger
                .log_error_event("nft", "ContentHashMismatch", &msg)
                .ok();
            return Err(ErrorDetection::ValidationError {
                message: msg,
                tx_id: None,
            });
        }

        send_net_cmd(NetCmd::SendTxKind(TxKind::NftMint(tx)))?;

        println!();
        println!(
            "{}",
            "✅ Certificate / NFT mint transaction submitted to mempool / network.".green()
        );
        println!("  NFT ID:        {}", nft_id_hex);
        println!("  Type (kind):   {}", kind);
        println!("  Schema:        {}", schema);
        println!("  Owner wallet:  {}", owner_wallet);
        println!("  Title:         {}", title);
        println!("  File:          {} ({} bytes)", file_name, file_size);
        println!("  Content hash:  {}", content_hash_hex);

        let receipt = CertificateReceipt {
            nft_id_hex,
            owner_wallet,
            file_name,
            file_size_bytes: file_size,
            content_hash_hex,
            title,
            description,
            created_at_utc: created_at,
            edition: if edition_input.is_empty() {
                None
            } else {
                Some(edition_input)
            },
            kind,
            schema,
        };

        if let Err(e) = receipt.validate() {
            let msg = format!("Invalid NFT receipt (won't write files): {e:?}");
            json_logger
                .log_error_event("nft", "ReceiptInvalid", &msg)
                .ok();
        } else if let Err(e) = self.write_certificate_receipt_files(audit_dir, pdf_dir, &receipt) {
            let msg = format!("Failed to write NFT receipt files: {e:?}");
            json_logger
                .log_error_event("nft", "ReceiptWriteFailed", &msg)
                .ok();
        }

        Ok(())
    }

    fn read_rwa_parse_retry<T, F>(
        prompt: &str,
        stage: &'static str,
        cap: usize,
        mut parser: F,
    ) -> Result<T, ErrorDetection>
    where
        F: FnMut(&str) -> Result<T, ErrorDetection>,
    {
        for attempt in 1..=RWA_MAX_RETRIES {
            let value = match Self::read_trimmed_prompt(prompt, stage, cap) {
                Ok(v) => v,
                Err(e) => {
                    Self::print_rwa_invalid_attempt(stage, attempt, &e);
                    continue;
                }
            };

            match parser(&value) {
                Ok(parsed) => return Ok(parsed),
                Err(e) => Self::print_rwa_invalid_attempt(stage, attempt, &e),
            }
        }

        Err(Self::rwa_too_many_attempts(stage))
    }

    fn read_rwa_wallet_retry(
        prompt: &str,
        stage: &'static str,
        default_wallet: Option<&str>,
        label: &'static str,
        require_register_validation: bool,
    ) -> Result<String, ErrorDetection> {
        for attempt in 1..=RWA_MAX_RETRIES {
            let raw = match Self::read_trimmed_prompt(
                prompt,
                stage,
                GlobalConfiguration::MAX_INPUT_BYTES,
            ) {
                Ok(v) => v,
                Err(e) => {
                    Self::print_rwa_invalid_attempt(stage, attempt, &e);
                    continue;
                }
            };

            let candidate = if raw.trim().is_empty() {
                match default_wallet {
                    Some(default) if !default.trim().is_empty() => default.trim().to_string(),
                    _ => {
                        Self::print_rwa_invalid_attempt_message(
                            stage,
                            attempt,
                            "Wallet is required here; no default wallet is available.",
                        );
                        continue;
                    }
                }
            } else {
                raw
            };

            let wallet = match Self::canonicalize_wallet(&candidate, label) {
                Ok(v) => v,
                Err(e) => {
                    Self::print_rwa_invalid_attempt(stage, attempt, &e);
                    continue;
                }
            };

            if require_register_validation && let Err(e) = RegisterNodeTx::new(wallet.clone()) {
                Self::print_rwa_invalid_attempt_message(
                    stage,
                    attempt,
                    &format!("Wallet is not a valid Remzar address: {e:?}"),
                );
                continue;
            }

            return Ok(wallet);
        }

        Err(Self::rwa_too_many_attempts(stage))
    }

    fn print_rwa_invalid_attempt(stage: &'static str, attempt: usize, err: &ErrorDetection) {
        println!(
            "{}",
            format!(
                "❌ Invalid RWA input at {stage}. Attempt {}/{}. Details: {:?}",
                attempt, RWA_MAX_RETRIES, err
            )
            .red()
        );
    }

    fn print_rwa_invalid_attempt_message(stage: &'static str, attempt: usize, message: &str) {
        println!(
            "{}",
            format!(
                "❌ Invalid RWA input at {stage}. Attempt {}/{}. {message}",
                attempt, RWA_MAX_RETRIES
            )
            .red()
        );
    }

    fn rwa_too_many_attempts(stage: &'static str) -> ErrorDetection {
        println!(
            "{}",
            format!(
                "↩️ Too many invalid RWA attempts at {stage}. Returning to menu without minting."
            )
            .yellow()
        );

        ErrorDetection::ValidationError {
            message: format!("Too many invalid RWA attempts at {stage}"),
            tx_id: None,
        }
    }

    fn hash_text_64(value: &str) -> RwaHash64 {
        RwaHash64::compute_from_bytes(value.trim().as_bytes())
    }

    fn parse_u128_input(label: &'static str, value: &str) -> Result<u128, ErrorDetection> {
        let s = value.trim();

        if s.is_empty() {
            return Err(ErrorDetection::ValidationError {
                message: format!("{label} cannot be empty"),
                tx_id: None,
            });
        }

        if s.len() > 64
            || s.starts_with('-')
            || s.starts_with('+')
            || s.contains('e')
            || s.contains('E')
            || s.as_bytes().iter().any(|b| b.is_ascii_whitespace())
            || !s.as_bytes().iter().all(|b| b.is_ascii_digit())
        {
            return Err(ErrorDetection::ValidationError {
                message: format!("{label} must be a non-negative whole number"),
                tx_id: None,
            });
        }

        s.parse::<u128>()
            .map_err(|e| ErrorDetection::ValidationError {
                message: format!("{label} is outside supported u128 range: {e}"),
                tx_id: None,
            })
    }

    fn parse_optional_u128_input(
        label: &'static str,
        value: &str,
    ) -> Result<Option<u128>, ErrorDetection> {
        if value.trim().is_empty() {
            return Ok(None);
        }
        Ok(Some(Self::parse_u128_input(label, value)?))
    }

    fn parse_optional_u32_input(
        label: &'static str,
        value: &str,
    ) -> Result<Option<u32>, ErrorDetection> {
        let Some(v) = Self::parse_optional_u128_input(label, value)? else {
            return Ok(None);
        };

        u32::try_from(v)
            .map(Some)
            .map_err(|_| ErrorDetection::ValidationError {
                message: format!("{label} exceeds u32::MAX"),
                tx_id: None,
            })
    }

    fn parse_optional_unix_timestamp(
        label: &'static str,
        value: &str,
    ) -> Result<Option<u64>, ErrorDetection> {
        let Some(v) = Self::parse_optional_u128_input(label, value)? else {
            return Ok(None);
        };

        let ts = u64::try_from(v).map_err(|_| ErrorDetection::ValidationError {
            message: format!("{label} exceeds u64::MAX"),
            tx_id: None,
        })?;

        TimePolicy::validate_unix_secs_structural(label, ts)?;
        Ok(Some(ts))
    }

    fn parse_u8_input(label: &'static str, value: &str) -> Result<u8, ErrorDetection> {
        let v = Self::parse_u128_input(label, value)?;
        u8::try_from(v).map_err(|_| ErrorDetection::ValidationError {
            message: format!("{label} exceeds u8::MAX"),
            tx_id: None,
        })
    }

    fn parse_usd_cents_input(label: &'static str, value: &str) -> Result<u128, ErrorDetection> {
        let s = value.trim();

        if s.is_empty() {
            return Err(ErrorDetection::ValidationError {
                message: format!("{label} cannot be empty"),
                tx_id: None,
            });
        }

        if s.len() > 64
            || s.starts_with('-')
            || s.starts_with('+')
            || s.contains('e')
            || s.contains('E')
            || s.as_bytes().iter().any(|b| b.is_ascii_whitespace())
        {
            return Err(ErrorDetection::ValidationError {
                message: format!("{label} must be a positive decimal dollar amount"),
                tx_id: None,
            });
        }

        let (whole_part, frac_part) = match s.split_once('.') {
            Some((whole, frac)) => {
                if frac.contains('.') {
                    return Err(ErrorDetection::ValidationError {
                        message: format!("{label} contains more than one decimal point"),
                        tx_id: None,
                    });
                }
                (whole, frac)
            }
            None => (s, ""),
        };

        let whole_str = if whole_part.is_empty() {
            "0"
        } else {
            whole_part
        };

        if !whole_str.as_bytes().iter().all(|b| b.is_ascii_digit())
            || !frac_part.as_bytes().iter().all(|b| b.is_ascii_digit())
            || frac_part.len() > 2
        {
            return Err(ErrorDetection::ValidationError {
                message: format!("{label} must have at most 2 decimal places"),
                tx_id: None,
            });
        }

        let whole = whole_str
            .parse::<u128>()
            .map_err(|e| ErrorDetection::ValidationError {
                message: format!("{label} whole-dollar value is invalid: {e}"),
                tx_id: None,
            })?;

        let mut cents = 0u128;
        for &b in frac_part.as_bytes() {
            let digit =
                u128::from(
                    b.checked_sub(b'0')
                        .ok_or_else(|| ErrorDetection::ValidationError {
                            message: format!("{label} cents contains a non-digit byte"),
                            tx_id: None,
                        })?,
                );

            cents = cents
                .checked_mul(10)
                .and_then(|v| v.checked_add(digit))
                .ok_or_else(|| ErrorDetection::ValidationError {
                    message: format!("{label} cents value overflow"),
                    tx_id: None,
                })?;
        }

        for _ in frac_part.len()..2 {
            cents = cents
                .checked_mul(10)
                .ok_or_else(|| ErrorDetection::ValidationError {
                    message: format!("{label} cents value overflow"),
                    tx_id: None,
                })?;
        }

        let total = whole
            .checked_mul(100)
            .and_then(|v| v.checked_add(cents))
            .ok_or_else(|| ErrorDetection::ValidationError {
                message: format!("{label} amount overflow"),
                tx_id: None,
            })?;

        if total == 0 {
            return Err(ErrorDetection::ValidationError {
                message: format!("{label} must be greater than zero"),
                tx_id: None,
            });
        }

        Ok(total)
    }

    fn parse_optional_usd_cents_input(
        label: &'static str,
        value: &str,
    ) -> Result<Option<u128>, ErrorDetection> {
        if value.trim().is_empty() {
            return Ok(None);
        }
        Ok(Some(Self::parse_usd_cents_input(label, value)?))
    }

    fn parse_percent_to_bps_input(label: &'static str, value: &str) -> Result<u32, ErrorDetection> {
        let s = value.trim().trim_end_matches('%').trim();

        if s.is_empty() {
            return Err(ErrorDetection::ValidationError {
                message: format!("{label} cannot be empty"),
                tx_id: None,
            });
        }

        if s.len() > 32
            || s.starts_with('-')
            || s.starts_with('+')
            || s.contains('e')
            || s.contains('E')
            || s.as_bytes().iter().any(|b| b.is_ascii_whitespace())
        {
            return Err(ErrorDetection::ValidationError {
                message: format!("{label} must be a non-negative percent like 4.5 or 4.50"),
                tx_id: None,
            });
        }

        let (whole_part, frac_part) = match s.split_once('.') {
            Some((whole, frac)) => {
                if frac.contains('.') {
                    return Err(ErrorDetection::ValidationError {
                        message: format!("{label} contains more than one decimal point"),
                        tx_id: None,
                    });
                }
                (whole, frac)
            }
            None => (s, ""),
        };

        let whole_str = if whole_part.is_empty() {
            "0"
        } else {
            whole_part
        };

        if !whole_str.as_bytes().iter().all(|b| b.is_ascii_digit())
            || !frac_part.as_bytes().iter().all(|b| b.is_ascii_digit())
            || frac_part.len() > 2
        {
            return Err(ErrorDetection::ValidationError {
                message: format!("{label} must have at most 2 decimal places"),
                tx_id: None,
            });
        }

        let whole = whole_str
            .parse::<u32>()
            .map_err(|e| ErrorDetection::ValidationError {
                message: format!("{label} whole percent is invalid: {e}"),
                tx_id: None,
            })?;

        let mut frac = 0u32;
        for &b in frac_part.as_bytes() {
            let digit =
                u32::from(
                    b.checked_sub(b'0')
                        .ok_or_else(|| ErrorDetection::ValidationError {
                            message: format!(
                                "{label} fractional percent contains a non-digit byte"
                            ),
                            tx_id: None,
                        })?,
                );

            frac = frac
                .checked_mul(10)
                .and_then(|v| v.checked_add(digit))
                .ok_or_else(|| ErrorDetection::ValidationError {
                    message: format!("{label} fractional percent overflow"),
                    tx_id: None,
                })?;
        }

        for _ in frac_part.len()..2 {
            frac = frac
                .checked_mul(10)
                .ok_or_else(|| ErrorDetection::ValidationError {
                    message: format!("{label} fractional percent overflow"),
                    tx_id: None,
                })?;
        }

        whole
            .checked_mul(100)
            .and_then(|v| v.checked_add(frac))
            .ok_or_else(|| ErrorDetection::ValidationError {
                message: format!("{label} basis-point value overflow"),
                tx_id: None,
            })
    }

    fn parse_csv_strings(value: &str) -> Vec<String> {
        value
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToOwned::to_owned)
            .collect()
    }

    fn read_rwa_asset_class_interactive() -> Result<RwaAssetClass, ErrorDetection> {
        loop {
            println!();
            println!("{}", "Select RWA asset class:".cyan());
            println!("  [1] Real estate");
            println!("  [2] Treasury");
            println!("  [3] Money market");
            println!("  [4] Private credit");
            println!("  [5] Invoice");
            println!("  [6] Commodity");
            println!("  [7] Precious metal");
            println!("  [8] Cash equivalent");
            println!("  [9] Equity");
            println!("  [10] Fund share");
            println!("  [11] Bond");
            println!("  [12] Carbon credit");
            println!("  [13] Intellectual property");
            println!("  [14] Equipment");
            println!("  [15] Other");
            print!("Asset class (1-15): ");
            Self::flush_stdout("rwa.asset_class.flush")?;

            let choice = Self::read_line_capped(
                "rwa.asset_class.read",
                GlobalConfiguration::MAX_INPUT_BYTES,
            )?;

            match choice.trim() {
                "1" => return Ok(RwaAssetClass::RealEstate),
                "2" => return Ok(RwaAssetClass::Treasury),
                "3" => return Ok(RwaAssetClass::MoneyMarket),
                "4" => return Ok(RwaAssetClass::PrivateCredit),
                "5" => return Ok(RwaAssetClass::Invoice),
                "6" => return Ok(RwaAssetClass::Commodity),
                "7" => return Ok(RwaAssetClass::PreciousMetal),
                "8" => return Ok(RwaAssetClass::CashEquivalent),
                "9" => return Ok(RwaAssetClass::Equity),
                "10" => return Ok(RwaAssetClass::FundShare),
                "11" => return Ok(RwaAssetClass::Bond),
                "12" => return Ok(RwaAssetClass::CarbonCredit),
                "13" => return Ok(RwaAssetClass::IntellectualProperty),
                "14" => return Ok(RwaAssetClass::Equipment),
                "15" => return Ok(RwaAssetClass::Other),
                _ => println!("{}", "❌ Please type a number from 1 to 15.".red()),
            }
        }
    }

    fn read_rwa_payout_frequency_interactive() -> Result<RwaPayoutFrequency, ErrorDetection> {
        loop {
            println!();
            println!("{}", "Select RWA payout frequency:".cyan());
            println!("  [1] None");
            println!("  [2] Per second");
            println!("  [3] Daily");
            println!("  [4] Weekly");
            println!("  [5] Monthly");
            println!("  [6] Quarterly");
            println!("  [7] Semi-annual");
            println!("  [8] Annual");
            println!("  [9] At maturity");
            println!("  [10] Custom");
            print!("Payout frequency (1-10): ");
            Self::flush_stdout("rwa.payout_frequency.flush")?;

            let choice = Self::read_line_capped(
                "rwa.payout_frequency.read",
                GlobalConfiguration::MAX_INPUT_BYTES,
            )?;

            match choice.trim() {
                "1" => return Ok(RwaPayoutFrequency::None),
                "2" => return Ok(RwaPayoutFrequency::PerSecond),
                "3" => return Ok(RwaPayoutFrequency::Daily),
                "4" => return Ok(RwaPayoutFrequency::Weekly),
                "5" => return Ok(RwaPayoutFrequency::Monthly),
                "6" => return Ok(RwaPayoutFrequency::Quarterly),
                "7" => return Ok(RwaPayoutFrequency::SemiAnnual),
                "8" => return Ok(RwaPayoutFrequency::Annual),
                "9" => return Ok(RwaPayoutFrequency::AtMaturity),
                "10" => return Ok(RwaPayoutFrequency::Custom),
                _ => println!("{}", "❌ Please type a number from 1 to 10.".red()),
            }
        }
    }

    fn read_rwa_document_kind_interactive() -> Result<RwaDocumentKind, ErrorDetection> {
        loop {
            println!();
            println!("{}", "Select primary RWA legal document type:".cyan());
            println!("  [1] Asset deed");
            println!("  [2] Title insurance");
            println!("  [3] Appraisal");
            println!("  [4] Custody statement");
            println!("  [5] SPV filing");
            println!("  [6] Trust agreement");
            println!("  [7] Offering memorandum");
            println!("  [8] Subscription agreement");
            println!("  [9] Audit report");
            println!("  [10] Proof of reserve");
            println!("  [11] Insurance policy");
            println!("  [12] Court order");
            println!("  [13] Legal opinion");
            println!("  [14] Compliance policy");
            println!("  [15] Other");
            print!("Document type (1-15): ");
            Self::flush_stdout("rwa.document_kind.flush")?;

            let choice = Self::read_line_capped(
                "rwa.document_kind.read",
                GlobalConfiguration::MAX_INPUT_BYTES,
            )?;

            match choice.trim() {
                "1" => return Ok(RwaDocumentKind::AssetDeed),
                "2" => return Ok(RwaDocumentKind::TitleInsurance),
                "3" => return Ok(RwaDocumentKind::Appraisal),
                "4" => return Ok(RwaDocumentKind::CustodyStatement),
                "5" => return Ok(RwaDocumentKind::SpvFiling),
                "6" => return Ok(RwaDocumentKind::TrustAgreement),
                "7" => return Ok(RwaDocumentKind::OfferingMemorandum),
                "8" => return Ok(RwaDocumentKind::SubscriptionAgreement),
                "9" => return Ok(RwaDocumentKind::AuditReport),
                "10" => return Ok(RwaDocumentKind::ProofOfReserve),
                "11" => return Ok(RwaDocumentKind::InsurancePolicy),
                "12" => return Ok(RwaDocumentKind::CourtOrder),
                "13" => return Ok(RwaDocumentKind::LegalOpinion),
                "14" => return Ok(RwaDocumentKind::CompliancePolicy),
                "15" => return Ok(RwaDocumentKind::Other),
                _ => println!("{}", "❌ Please type a number from 1 to 15.".red()),
            }
        }
    }

    fn write_rwa_audit_files(
        &self,
        audit_dir: &Path,
        certificate: &RwaAssetCertificate,
        consensus_bytes: &[u8],
    ) -> Result<(PathBuf, PathBuf), ErrorDetection> {
        let base_dir: PathBuf = if audit_dir.as_os_str().is_empty() {
            PathBuf::from("data").join("rwa.certificate")
        } else {
            audit_dir.join("rwa.certificate")
        };

        fs::create_dir_all(&base_dir).map_err(|e| ErrorDetection::StorageError {
            message: format!(
                "Failed to create RWA certificate directory {}: {e}",
                base_dir.display()
            ),
        })?;

        let id_hex = certificate.certificate_id_hex();

        let json_path = base_dir.join(format!("rwa_certificate_{id_hex}.json"));
        let json = to_pretty_json(certificate)?;

        fs::write(&json_path, &json).map_err(|e| ErrorDetection::IoError {
            message: format!("Failed to write RWA JSON at {}: {e}", json_path.display()),
            code: e.raw_os_error(),
            source: Some(Box::new(e)),
        })?;

        let postcard_path = base_dir.join(format!("rwa_certificate_{id_hex}.postcard"));
        fs::write(&postcard_path, consensus_bytes).map_err(|e| ErrorDetection::IoError {
            message: format!(
                "Failed to write RWA postcard payload at {}: {e}",
                postcard_path.display()
            ),
            code: e.raw_os_error(),
            source: Some(Box::new(e)),
        })?;

        Ok((json_path, postcard_path))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_rwa_certificate_interactive(
        &mut self,
        local_wallet: &str,
        audit_dir: &Path,
        pdf_dir: &Path,
        json_logger: &JsonLogger,
        send_net_cmd: &mut dyn FnMut(NetCmd) -> Result<(), ErrorDetection>,
    ) -> Result<(), ErrorDetection> {
        const CONTENT_HASH_HEX_LEN: usize = 128;
        const MAX_RWA_DOCUMENT_BYTES: u64 = 25 * 1024 * 1024;

        println!();
        println!("{}", "🏦 RWA / Real-World Asset Certificate".cyan());
        println!(
            "{}",
            "This creates a Remzar RWA certificate as a postcard-serialized NFT payload. JSON is written only for human audit/export."
                .yellow()
        );

        let confirmed = Self::confirm_yes_no(
            &format!(
                "{} ",
                "Do you want to create a new RWA certificate? (yes/no):".yellow()
            ),
            "rwa.confirm",
        )?;

        if !confirmed {
            println!(
                "{}",
                "↩️  RWA creation cancelled, returning to menu.".yellow()
            );
            return Ok(());
        }

        println!();
        println!(
            "{}",
            "Issuer wallet address (press Enter to use local wallet):".cyan()
        );
        if !local_wallet.is_empty() {
            println!("(Default) {}", local_wallet.green());
        }

        let issuer_wallet = Self::read_rwa_wallet_retry(
            "Issuer wallet: ",
            "rwa.issuer.read",
            if local_wallet.is_empty() {
                None
            } else {
                Some(local_wallet)
            },
            "RWA issuer",
            true,
        )?;

        println!();
        println!(
            "{}",
            "Owner wallet address (press Enter to use issuer wallet):".cyan()
        );
        println!("(Default) {}", issuer_wallet.green());

        let owner_wallet = Self::read_rwa_wallet_retry(
            "Owner wallet: ",
            "rwa.owner.read",
            Some(&issuer_wallet),
            "RWA owner",
            true,
        )?;

        let asset_class = Self::read_rwa_asset_class_interactive()?;

        let asset_name = Self::read_rwa_parse_retry(
            "Asset name / certificate title: ",
            "rwa.asset_name.read",
            GlobalConfiguration::MAX_INPUT_BYTES,
            |s| {
                let v = s.trim().to_string();
                if v.is_empty() {
                    Err(ErrorDetection::ValidationError {
                        message: "Asset name cannot be empty".into(),
                        tx_id: None,
                    })
                } else {
                    Ok(v)
                }
            },
        )?;

        let asset_reference = Self::read_rwa_parse_retry(
            "Private/internal asset reference to hash (not stored raw): ",
            "rwa.asset_reference.read",
            GlobalConfiguration::MAX_INPUT_BYTES,
            |s| {
                let v = s.trim().to_string();
                if v.is_empty() {
                    Err(ErrorDetection::ValidationError {
                        message: "Asset reference cannot be empty".into(),
                        tx_id: None,
                    })
                } else {
                    Ok(v)
                }
            },
        )?;
        let asset_reference_hash = Self::hash_text_64(&asset_reference);

        let asset_valuation_usd_cents = Self::read_rwa_parse_retry(
            "Current asset valuation in USD (example 1250000.00): ",
            "rwa.valuation.read",
            GlobalConfiguration::MAX_INPUT_BYTES,
            |s| Self::parse_usd_cents_input("asset valuation USD", s),
        )?;

        let valuation_doc_note = Self::read_rwa_parse_retry(
            "Valuation/appraisal source reference to hash (not stored raw): ",
            "rwa.valuation_source.read",
            GlobalConfiguration::MAX_INPUT_BYTES,
            |s| {
                let v = s.trim().to_string();
                if v.is_empty() {
                    Err(ErrorDetection::ValidationError {
                        message: "Valuation source reference cannot be empty".into(),
                        tx_id: None,
                    })
                } else {
                    Ok(v)
                }
            },
        )?;
        let valuation_source_hash = Self::hash_text_64(&valuation_doc_note);

        let valuation_timestamp_unix = TimePolicy::now_unix_secs_runtime()?;

        let yield_bps = Self::read_rwa_parse_retry(
            "Yield / APY percent (example 4.50, use 0 for none): ",
            "rwa.yield.read",
            GlobalConfiguration::MAX_INPUT_BYTES,
            |s| Self::parse_percent_to_bps_input("yield/APY percent", s),
        )?;

        let payout_frequency = Self::read_rwa_payout_frequency_interactive()?;

        let maturity_timestamp_unix = Self::read_rwa_parse_retry(
            "Optional maturity UNIX timestamp in seconds (blank for none): ",
            "rwa.maturity.read",
            GlobalConfiguration::MAX_INPUT_BYTES,
            |s| Self::parse_optional_unix_timestamp("rwa.maturity_timestamp_unix", s),
        )?;

        let total_supply = Self::read_rwa_parse_retry(
            "Total fractional supply / units (example 1000000): ",
            "rwa.total_supply.read",
            GlobalConfiguration::MAX_INPUT_BYTES,
            |s| Self::parse_u128_input("total supply", s),
        )?;

        let decimals = Self::read_rwa_parse_retry(
            "Decimals for fractional units (0-18): ",
            "rwa.decimals.read",
            GlobalConfiguration::MAX_INPUT_BYTES,
            |s| Self::parse_u8_input("decimals", s),
        )?;

        let face_value_usd_cents_per_unit = Self::read_rwa_parse_retry(
            "Optional face value per unit in USD (blank for none): ",
            "rwa.face_value.read",
            GlobalConfiguration::MAX_INPUT_BYTES,
            |s| Self::parse_optional_usd_cents_input("face value per unit USD", s),
        )?;

        let minimum_transfer_units = Self::read_rwa_parse_retry(
            "Optional minimum transfer units (blank for none): ",
            "rwa.minimum_transfer.read",
            GlobalConfiguration::MAX_INPUT_BYTES,
            |s| Self::parse_optional_u128_input("minimum transfer units", s),
        )?;

        let legal_jurisdiction = Self::read_rwa_parse_retry(
            "Legal jurisdiction code (example US-DE, CA-ON, SG): ",
            "rwa.legal_jurisdiction.read",
            GlobalConfiguration::MAX_INPUT_BYTES,
            |s| {
                let v = s.trim().to_string();
                if v.is_empty() {
                    Err(ErrorDetection::ValidationError {
                        message: "Legal jurisdiction cannot be empty".into(),
                        tx_id: None,
                    })
                } else {
                    Ok(v)
                }
            },
        )?;

        let spv_identity = Self::read_rwa_parse_retry(
            "SPV / trustee / custodian identity to hash (not stored raw): ",
            "rwa.spv_identity.read",
            GlobalConfiguration::MAX_INPUT_BYTES,
            |s| {
                let v = s.trim().to_string();
                if v.is_empty() {
                    Err(ErrorDetection::ValidationError {
                        message: "SPV / trustee / custodian identity cannot be empty".into(),
                        tx_id: None,
                    })
                } else {
                    Ok(v)
                }
            },
        )?;
        let spv_or_trustee_identity_hash = Self::hash_text_64(&spv_identity);

        let trustee_wallet_input = Self::read_rwa_parse_retry(
            "Optional trustee/custodian wallet (blank for none): ",
            "rwa.trustee_wallet.read",
            GlobalConfiguration::MAX_INPUT_BYTES,
            |s| Ok::<String, ErrorDetection>(s.trim().to_string()),
        )?;
        let trustee_wallet = if trustee_wallet_input.is_empty() {
            None
        } else {
            Some(Self::canonicalize_wallet(
                &trustee_wallet_input,
                "RWA trustee",
            )?)
        };

        let legal_summary_input = Self::read_rwa_parse_retry(
            "Optional legal summary note (do not enter private KYC data): ",
            "rwa.legal_summary.read",
            GlobalConfiguration::MAX_INPUT_BYTES,
            |s| Ok::<String, ErrorDetection>(s.trim().to_string()),
        )?;
        let legal_summary = if legal_summary_input.is_empty() {
            None
        } else {
            Some(legal_summary_input)
        };

        let document_kind = Self::read_rwa_document_kind_interactive()?;

        let (_document_path, document_bytes, document_file_name) = Self::read_rwa_parse_retry(
            "Path to primary legal/off-chain document to hash: ",
            "rwa.document_path.read",
            GlobalConfiguration::MAX_INPUT_BYTES,
            |document_path_input| {
                let document_path = document_path_input.trim().to_string();

                if document_path.is_empty() {
                    return Err(ErrorDetection::ValidationError {
                        message: "RWA legal document path cannot be empty".into(),
                        tx_id: None,
                    });
                }

                let document_meta =
                    fs::metadata(&document_path).map_err(|e| ErrorDetection::IoError {
                        message: format!(
                            "Failed to stat RWA legal document {}: {e}",
                            document_path
                        ),
                        code: e.raw_os_error(),
                        source: Some(Box::new(e)),
                    })?;

                if !document_meta.is_file() || document_meta.len() == 0 {
                    return Err(ErrorDetection::ValidationError {
                        message: format!(
                            "RWA legal document is not a non-empty regular file: {document_path}"
                        ),
                        tx_id: None,
                    });
                }

                if document_meta.len() > MAX_RWA_DOCUMENT_BYTES {
                    return Err(ErrorDetection::ValidationError {
                        message: format!(
                            "RWA legal document too large ({} bytes). Max allowed is {} bytes.",
                            document_meta.len(),
                            MAX_RWA_DOCUMENT_BYTES
                        ),
                        tx_id: None,
                    });
                }

                let document_bytes =
                    fs::read(&document_path).map_err(|e| ErrorDetection::IoError {
                        message: format!(
                            "Failed to read RWA legal document {}: {e}",
                            document_path
                        ),
                        code: e.raw_os_error(),
                        source: Some(Box::new(e)),
                    })?;

                let document_file_name = Path::new(&document_path)
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("rwa_document")
                    .to_string();

                Ok((document_path, document_bytes, document_file_name))
            },
        )?;

        let document_hash = RwaHash64::compute_from_bytes(&document_bytes);
        println!("  Primary legal document hash: {}", document_hash.to_hex());

        let document_label_input = Self::read_rwa_parse_retry(
            "Optional document label (blank uses file name): ",
            "rwa.document_label.read",
            GlobalConfiguration::MAX_INPUT_BYTES,
            |s| Ok::<String, ErrorDetection>(s.trim().to_string()),
        )?;
        let document_label = if document_label_input.is_empty() {
            document_file_name.clone()
        } else {
            document_label_input
        };

        let document_uri_input = Self::read_rwa_parse_retry(
            "Document URI/CID (ipfs://, ar://, https://, remzar://) or blank for local hash URI: ",
            "rwa.document_uri.read",
            GlobalConfiguration::MAX_INPUT_BYTES,
            |s| Ok::<String, ErrorDetection>(s.trim().to_string()),
        )?;
        let document_uri = if document_uri_input.is_empty() {
            format!(
                "remzar://rwa/document/{}/{}",
                document_hash.to_hex(),
                document_file_name
            )
        } else {
            document_uri_input
        };

        let document_issued_at_unix = Some(TimePolicy::now_unix_secs_runtime()?);
        let mut primary_document = document_from_bytes(
            document_kind,
            document_label,
            document_uri,
            &document_bytes,
            1,
            document_issued_at_unix,
        )?;
        primary_document.issuer_identity_hash = Some(spv_or_trustee_identity_hash);

        let mut auditor_stamps = Vec::new();
        let add_auditor = Self::confirm_yes_no(
            &format!(
                "{} ",
                "Optional: add an auditor/proof-of-reserve stamp now? (yes/no):".yellow()
            ),
            "rwa.auditor.confirm",
        )?;

        if add_auditor {
            let auditor_identity = Self::read_rwa_parse_retry(
                "Auditor identity to hash (not stored raw): ",
                "rwa.auditor_identity.read",
                GlobalConfiguration::MAX_INPUT_BYTES,
                |s| {
                    let v = s.trim().to_string();
                    if v.is_empty() {
                        Err(ErrorDetection::ValidationError {
                            message: "Auditor identity cannot be empty".into(),
                            tx_id: None,
                        })
                    } else {
                        Ok(v)
                    }
                },
            )?;

            let statement_reference = Self::read_rwa_parse_retry(
                "Auditor statement/reference to hash (not stored raw): ",
                "rwa.auditor_statement.read",
                GlobalConfiguration::MAX_INPUT_BYTES,
                |s| {
                    let v = s.trim().to_string();
                    if v.is_empty() {
                        Err(ErrorDetection::ValidationError {
                            message: "Auditor statement/reference cannot be empty".into(),
                            tx_id: None,
                        })
                    } else {
                        Ok(v)
                    }
                },
            )?;

            let auditor_wallet_input = Self::read_rwa_parse_retry(
                "Optional auditor wallet (blank for none): ",
                "rwa.auditor_wallet.read",
                GlobalConfiguration::MAX_INPUT_BYTES,
                |s| Ok::<String, ErrorDetection>(s.trim().to_string()),
            )?;

            let auditor_wallet = if auditor_wallet_input.is_empty() {
                None
            } else {
                Some(Self::canonicalize_wallet(
                    &auditor_wallet_input,
                    "RWA auditor",
                )?)
            };

            let proof_uri_input = Self::read_rwa_parse_retry(
                "Optional auditor proof URI (ipfs://, ar://, https://, remzar://): ",
                "rwa.auditor_proof_uri.read",
                GlobalConfiguration::MAX_INPUT_BYTES,
                |s| Ok::<String, ErrorDetection>(s.trim().to_string()),
            )?;

            auditor_stamps.push(RwaAuditorVerification {
                auditor_wallet,
                auditor_identity_hash: Self::hash_text_64(&auditor_identity),
                statement_hash: Self::hash_text_64(&statement_reference),
                verified_at_unix: TimePolicy::now_unix_secs_runtime()?,
                expires_at_unix: None,
                proof_uri: if proof_uri_input.is_empty() {
                    None
                } else {
                    Some(proof_uri_input)
                },
            });
        }

        let kyc_registry_wallet_input = Self::read_rwa_parse_retry(
            "Optional KYC registry wallet (blank for none): ",
            "rwa.kyc_registry_wallet.read",
            GlobalConfiguration::MAX_INPUT_BYTES,
            |s| Ok::<String, ErrorDetection>(s.trim().to_string()),
        )?;
        let kyc_registry_wallet = if kyc_registry_wallet_input.is_empty() {
            None
        } else {
            Some(Self::canonicalize_wallet(
                &kyc_registry_wallet_input,
                "RWA KYC registry",
            )?)
        };

        let kyc_registry_reference_input = Self::read_rwa_parse_retry(
            "Optional KYC registry reference URI/text (blank for none): ",
            "rwa.kyc_registry_reference.read",
            GlobalConfiguration::MAX_INPUT_BYTES,
            |s| Ok::<String, ErrorDetection>(s.trim().to_string()),
        )?;
        let kyc_registry_reference = if kyc_registry_reference_input.is_empty() {
            None
        } else {
            Some(kyc_registry_reference_input)
        };

        let allowed_jurisdictions_input = Self::read_rwa_parse_retry(
            "Allowed jurisdictions comma-separated (blank for no allow-list): ",
            "rwa.allowed_jurisdictions.read",
            GlobalConfiguration::MAX_INPUT_BYTES,
            |s| Ok::<String, ErrorDetection>(s.trim().to_string()),
        )?;
        let allowed_jurisdictions = Self::parse_csv_strings(&allowed_jurisdictions_input);

        let blocked_jurisdictions_input = Self::read_rwa_parse_retry(
            "Blocked jurisdictions comma-separated (blank for none): ",
            "rwa.blocked_jurisdictions.read",
            GlobalConfiguration::MAX_INPUT_BYTES,
            |s| Ok::<String, ErrorDetection>(s.trim().to_string()),
        )?;
        let blocked_jurisdictions = Self::parse_csv_strings(&blocked_jurisdictions_input);

        let accredited_investor_required = Self::confirm_yes_no(
            &format!(
                "{} ",
                "Require accredited-investor/KYC-approved holder status? (yes/no):".yellow()
            ),
            "rwa.accredited.confirm",
        )?;

        let max_investors = Self::read_rwa_parse_retry(
            "Optional maximum investor count (blank for none): ",
            "rwa.max_investors.read",
            GlobalConfiguration::MAX_INPUT_BYTES,
            |s| Self::parse_optional_u32_input("max investors", s),
        )?;

        let transfer_lock_until_unix = Self::read_rwa_parse_retry(
            "Optional transfer lock-until UNIX timestamp (blank for none): ",
            "rwa.transfer_lock.read",
            GlobalConfiguration::MAX_INPUT_BYTES,
            |s| Self::parse_optional_unix_timestamp("transfer lock-until timestamp", s),
        )?;

        let freeze_authority_wallet = Some(Self::read_rwa_wallet_retry(
            "Freeze authority wallet (blank uses issuer wallet): ",
            "rwa.freeze_authority.read",
            Some(&issuer_wallet),
            "RWA freeze authority",
            true,
        )?);

        let clawback_enabled = Self::confirm_yes_no(
            &format!(
                "{} ",
                "Enable legal clawback authority for court/order recovery? (yes/no):".yellow()
            ),
            "rwa.clawback.confirm",
        )?;

        let clawback_authority_wallet = if clawback_enabled {
            Some(Self::read_rwa_wallet_retry(
                "Clawback authority wallet (blank uses issuer wallet): ",
                "rwa.clawback_authority.read",
                Some(&issuer_wallet),
                "RWA clawback authority",
                true,
            )?)
        } else {
            None
        };

        let rule_note = Self::read_rwa_parse_retry(
            "Optional compliance rule note (blank for none): ",
            "rwa.rule_note.read",
            GlobalConfiguration::MAX_INPUT_BYTES,
            |s| Ok::<String, ErrorDetection>(s.trim().to_string()),
        )?;
        let rule_notes = if rule_note.is_empty() {
            Vec::new()
        } else {
            vec![rule_note]
        };

        let now_unix = TimePolicy::now_unix_secs_runtime()?;

        let core = RwaCoreFinancialData {
            asset_class,
            asset_name,
            asset_reference_hash,
            asset_valuation_usd_cents,
            valuation_timestamp_unix,
            valuation_source_hash,
            yield_bps,
            payout_frequency,
            maturity_timestamp_unix,
            total_supply,
            decimals,
            face_value_usd_cents_per_unit,
            minimum_transfer_units,
        };

        let legal = RwaLegalOwnershipData {
            legal_jurisdiction,
            spv_or_trustee_identity_hash,
            trustee_wallet,
            legal_summary,
            documents: vec![primary_document],
            auditor_stamps,
        };

        let compliance = RwaComplianceRules {
            kyc_registry_wallet,
            kyc_registry_reference,
            allowed_jurisdictions,
            blocked_jurisdictions,
            accredited_investor_required,
            max_investors,
            transfer_lock_until_unix,
            transfers_paused: false,
            freeze_authority_wallet,
            clawback_authority_wallet,
            clawback_enabled,
            rule_notes,
        };

        let technical = RwaTechnicalBlockchainData {
            token_standard: RwaTokenStandard::RemzarNativeRwa,
            contract_address: Some("remzar://tokens/rwa_asset_certificate".to_string()),
            minting_timestamp_unix: None,
            minting_block: None,
            mint_tx_hash: None,
        };

        let mut random_entropy = [0u8; RWA_ID_BYTES];
        rand::rng().fill(&mut random_entropy);

        let mut entropy = Vec::new();
        entropy.extend_from_slice(&random_entropy);
        entropy.extend_from_slice(issuer_wallet.as_bytes());
        entropy.extend_from_slice(owner_wallet.as_bytes());
        entropy.extend_from_slice(&asset_reference_hash.0);
        entropy.extend_from_slice(&document_hash.0);
        entropy.extend_from_slice(&now_unix.to_be_bytes());

        let certificate_id = derive_certificate_id_from_entropy(&entropy)?;

        let certificate = RwaAssetCertificate::new(
            certificate_id,
            &issuer_wallet,
            &owner_wallet,
            core,
            legal,
            compliance,
            technical,
            now_unix,
        )?;

        let nft_id = certificate.certificate_id.0;
        let nft_id_hex = certificate.certificate_id_hex();

        let content_bytes = certificate.to_nft_content_bytes()?;
        let rwa_content_hash_hex = certificate.content_hash_hex()?;

        let tx = NftMintTx::from_content_bytes(
            nft_id,
            certificate.nft_title(),
            certificate.nft_description(),
            &content_bytes,
        );

        let content_hash_hex = hex::encode(tx.content_hash);
        debug_assert_eq!(content_hash_hex.len(), CONTENT_HASH_HEX_LEN);

        let local_expected = RemzarHash::compute_bytes_hash_hex(&content_bytes);
        if local_expected != content_hash_hex || rwa_content_hash_hex != content_hash_hex {
            let msg = format!(
                "RWA content hash mismatch: tx={}, local={}, rwa={}",
                content_hash_hex, local_expected, rwa_content_hash_hex
            );
            json_logger
                .log_error_event("rwa", "RwaContentHashMismatch", &msg)
                .ok();
            return Err(ErrorDetection::ValidationError {
                message: msg,
                tx_id: None,
            });
        }

        println!();
        println!("{}", "Review RWA certificate before mint:".cyan());
        println!("  NFT / RWA ID:          {}", nft_id_hex);
        println!("  Type (kind):           {}", RWA_KIND);
        println!("  Schema:                {}", RWA_SCHEMA);
        println!("  Issuer wallet:         {}", issuer_wallet);
        println!("  Owner wallet:          {}", owner_wallet);
        println!("  Asset name:            {}", certificate.core.asset_name);
        println!(
            "  Valuation USD cents:   {}",
            certificate.core.asset_valuation_usd_cents
        );
        println!("  Yield bps:             {}", certificate.core.yield_bps);
        println!("  Total supply:          {}", certificate.core.total_supply);
        println!(
            "  Metadata hash:         {}",
            certificate.metadata_hash_hex()
        );
        println!("  Content hash:          {}", content_hash_hex);

        let submit_confirmed = Self::confirm_yes_no(
            &format!(
                "{} ",
                "Submit this RWA certificate mint transaction? (yes/no):".yellow()
            ),
            "rwa.submit.confirm",
        )?;

        if !submit_confirmed {
            println!("{}", "↩️  RWA mint cancelled before submission.".yellow());
            println!("{}", "No RWA mint was submitted.".yellow());
            return Ok(());
        }

        send_net_cmd(NetCmd::SendTxKind(TxKind::NftMint(tx)))?;

        let (rwa_json_path, rwa_postcard_path) =
            self.write_rwa_audit_files(audit_dir, &certificate, &content_bytes)?;

        let created_at_utc = Self::runtime_utc_timestamp()?;

        let receipt = CertificateReceipt {
            nft_id_hex: nft_id_hex.clone(),
            owner_wallet: owner_wallet.clone(),
            file_name: rwa_postcard_path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("rwa_certificate.postcard")
                .to_string(),
            file_size_bytes: content_bytes.len(),
            content_hash_hex: content_hash_hex.clone(),
            title: certificate.nft_title(),
            description: certificate.nft_description(),
            created_at_utc,
            edition: None,
            kind: RWA_KIND.to_string(),
            schema: RWA_SCHEMA.to_string(),
        };

        if let Err(e) = receipt.validate() {
            let msg = format!("Invalid RWA receipt (won't write certificate PDF/JSON): {e:?}");
            json_logger
                .log_error_event("rwa", "RwaReceiptInvalid", &msg)
                .ok();
        } else if let Err(e) = self.write_certificate_receipt_files(audit_dir, pdf_dir, &receipt) {
            let msg = format!("Failed to write RWA certificate receipt files: {e:?}");
            json_logger
                .log_error_event("rwa", "RwaReceiptWriteFailed", &msg)
                .ok();
        }

        println!();
        println!(
            "{}",
            "✅ RWA certificate mint transaction submitted to mempool / network.".green()
        );
        println!("  NFT / RWA ID:          {}", nft_id_hex);
        println!("  Type (kind):           {}", RWA_KIND);
        println!("  Schema:                {}", RWA_SCHEMA);
        println!("  Issuer wallet:         {}", issuer_wallet);
        println!("  Owner wallet:          {}", owner_wallet);
        println!("  Asset name:            {}", certificate.core.asset_name);
        println!(
            "  Valuation USD cents:   {}",
            certificate.core.asset_valuation_usd_cents
        );
        println!("  Yield bps:             {}", certificate.core.yield_bps);
        println!("  Total supply:          {}", certificate.core.total_supply);
        println!(
            "  Metadata hash:         {}",
            certificate.metadata_hash_hex()
        );
        println!("  Content hash:          {}", content_hash_hex);
        println!("  RWA JSON audit file:   {}", rwa_json_path.display());
        println!("  RWA postcard payload:  {}", rwa_postcard_path.display());
        println!(
            "{}",
            "  Note: use the .postcard payload for local hash verification; the JSON file is human-readable audit/export only."
                .yellow()
        );

        Ok(())
    }

    fn write_certificate_receipt_files(
        &self,
        audit_dir: &Path,
        pdf_dir: &Path,
        receipt: &CertificateReceipt,
    ) -> Result<(), ErrorDetection> {
        const MAX_PDF_BYTES: usize = 10 * 1024 * 1024;

        #[allow(clippy::float_arithmetic)]
        fn build_certificate_pdf(receipt: &CertificateReceipt) -> Vec<u8> {
            const PAGE_W: f32 = 595.0;
            const PAGE_H: f32 = 842.0;
            const MARGIN_L: f32 = 50.0;
            const MARGIN_T: f32 = 40.0;
            const FONT_SIZE: f32 = 10.0;
            const LEADING: f32 = 13.0;
            const CHARS_PER_LINE: usize = 90;

            fn wrap_chunks(s: &str) -> Vec<String> {
                let chars: Vec<char> = s.chars().collect();
                chars
                    .chunks(CHARS_PER_LINE)
                    .map(|chunk| chunk.iter().collect::<String>())
                    .collect()
            }

            fn write_line(c: &mut Content, txt: &str, x: f32, y: f32) {
                c.begin_text();
                c.set_font(Name(b"F1"), FONT_SIZE);
                c.set_leading(LEADING);
                c.set_text_matrix([1.0, 0.0, 0.0, 1.0, x, y]);
                c.show(Str(txt.as_bytes()));
                c.end_text();
            }

            let mut pdf = Pdf::new();
            let catalog_id = Ref::new(1);
            let pages_id = Ref::new(2);
            let font_id = Ref::new(3);

            pdf.catalog(catalog_id).pages(pages_id);
            pdf.type1_font(font_id).base_font(Name(b"Courier"));

            let mut content = Content::new();
            let mut y = PAGE_H - MARGIN_T;

            let edition_str = receipt.edition.as_deref().unwrap_or("-");

            let mut lines: Vec<String> = vec![
                "Remzar NFT Certificate".to_string(),
                String::new(),
                format!("Kind: {}", receipt.kind),
                format!("Schema: {}", receipt.schema),
                String::new(),
                format!("NFT ID: {}", receipt.nft_id_hex),
                format!("Owner wallet: {}", receipt.owner_wallet),
                String::new(),
                format!(
                    "File: {} ({} bytes)",
                    receipt.file_name, receipt.file_size_bytes
                ),
                format!("Content hash: {}", receipt.content_hash_hex),
                format!("Title: {}", receipt.title),
                String::new(),
                "Description:".to_string(),
            ];

            for raw_part in receipt.description.split(" | ") {
                let part = raw_part.trim();
                if part.is_empty() {
                    continue;
                }
                for seg in wrap_chunks(part) {
                    lines.push(format!("  - {}", seg));
                }
            }

            lines.push(String::new());
            lines.push(format!("Edition: {}", edition_str));
            lines.push(format!("Created (UTC): {}", receipt.created_at_utc));

            for line in lines {
                if line.is_empty() {
                    y -= LEADING;
                    continue;
                }
                write_line(&mut content, &line, MARGIN_L, y);
                y -= LEADING;
            }

            let page_id = Ref::new(4);
            let cont_id = Ref::new(5);

            pdf.page(page_id)
                .parent(pages_id)
                .media_box(Rect::new(0.0, 0.0, PAGE_W, PAGE_H))
                .contents(cont_id)
                .resources()
                .fonts()
                .pair(Name(b"F1"), font_id);

            let stream = content.finish();
            pdf.stream(cont_id, &stream);
            pdf.pages(pages_id).kids([page_id]).count(1);

            pdf.finish()
        }

        receipt.validate()?;

        let base_dir: PathBuf = if audit_dir.as_os_str().is_empty() {
            PathBuf::from("data").join("nft.certificate")
        } else {
            audit_dir.to_path_buf()
        };

        fs::create_dir_all(&base_dir).map_err(|e| ErrorDetection::StorageError {
            message: format!(
                "Failed to create certificate directory {}: {e}",
                base_dir.display()
            ),
        })?;

        let json_path = base_dir.join(format!("certificate_{}.json", receipt.nft_id_hex));
        let json =
            serde_json::to_vec_pretty(receipt).map_err(|e| ErrorDetection::SerializationError {
                details: format!("serialize certificate JSON: {e}"),
            })?;

        fs::write(&json_path, &json).map_err(|e| ErrorDetection::IoError {
            message: format!(
                "Failed to write certificate JSON at {}: {e}",
                json_path.display()
            ),
            code: e.raw_os_error(),
            source: Some(Box::new(e)),
        })?;

        println!(
            "📄 NFT JSON certificate written to: {}",
            json_path.display()
        );

        let pdf_dir_final = if pdf_dir.as_os_str().is_empty() {
            base_dir
        } else {
            pdf_dir.to_path_buf()
        };

        fs::create_dir_all(&pdf_dir_final).map_err(|e| ErrorDetection::StorageError {
            message: format!(
                "Failed to create certificate PDF directory {}: {e}",
                pdf_dir_final.display()
            ),
        })?;

        let pdf_path = pdf_dir_final.join(format!("certificate_{}.pdf", receipt.nft_id_hex));
        let pdf_bytes = build_certificate_pdf(receipt);

        if pdf_bytes.len() > MAX_PDF_BYTES {
            return Err(ErrorDetection::ValidationError {
                message: format!("Generated PDF too large ({} bytes)", pdf_bytes.len()),
                tx_id: None,
            });
        }

        fs::write(&pdf_path, &pdf_bytes).map_err(|e| ErrorDetection::IoError {
            message: format!(
                "Failed to write certificate PDF at {}: {e}",
                pdf_path.display()
            ),
            code: e.raw_os_error(),
            source: Some(Box::new(e)),
        })?;

        println!("📑 NFT PDF certificate written to: {}", pdf_path.display());
        Ok(())
    }

    fn read_trimmed_prompt(
        prompt: &str,
        stage: &'static str,
        cap: usize,
    ) -> Result<String, ErrorDetection> {
        print!("{prompt}");
        Self::flush_stdout(stage)?;
        let line = Self::read_line_capped(stage, cap)?;
        Ok(line.trim().to_string())
    }

    fn load_wallet_for_digital_id(
        opts: &NodeOpts,
        wallet_address: &str,
        passphrase: &str,
    ) -> Result<MLDSA65Wallet, ErrorDetection> {
        let wallet_address = Self::canonicalize_wallet(wallet_address, "Digital I.D.")?;

        let directory = DirectoryDB::from_node_opts(opts).map_err(|e| ErrorDetection::IoError {
            message: format!("Failed to initialize directories for Digital I.D. wallet load: {e}"),
            code: None,
            source: None,
        })?;

        directory
            .create_wallets_directory()
            .map_err(|e| ErrorDetection::IoError {
                message: format!("Failed to create/check wallets directory: {e}"),
                code: None,
                source: None,
            })?;

        let wallet_file = directory
            .wallets_path
            .join(format!("{wallet_address}.wallet"));

        let encrypted_secret = fs::read(&wallet_file).map_err(|e| ErrorDetection::IoError {
            message: format!(
                "Failed to read wallet file for Digital I.D. at {}: {e}",
                wallet_file.display()
            ),
            code: e.raw_os_error(),
            source: Some(Box::new(e)),
        })?;

        let secret_bytes: Zeroizing<Vec<u8>> = Zeroizing::new(
            Cryption::decrypt_private_key_bytes(&encrypted_secret, passphrase).map_err(|e| {
                ErrorDetection::CryptographicError {
                    message: format!("Digital I.D. wallet passphrase verification failed: {e}"),
                }
            })?,
        );

        if secret_bytes.len() != ml_dsa_65::SK_LEN {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Digital I.D. decrypted wallet secret has invalid length: expected {}, got {}",
                    ml_dsa_65::SK_LEN,
                    secret_bytes.len()
                ),
                tx_id: None,
            });
        }

        let secret_arr: [u8; ml_dsa_65::SK_LEN] =
            secret_bytes
                .as_slice()
                .try_into()
                .map_err(|_| ErrorDetection::ValidationError {
                    message: format!(
                        "Failed to convert Digital I.D. wallet secret to [u8; {}]",
                        ml_dsa_65::SK_LEN
                    ),
                    tx_id: None,
                })?;

        let sk = ml_dsa_65::PrivateKey::try_from_bytes(secret_arr).map_err(|e| {
            ErrorDetection::CryptographicError {
                message: format!("Digital I.D. wallet secret is not a valid ML-DSA-65 key: {e}"),
            }
        })?;

        let pk = sk.get_public_key();
        let public_bytes = pk.into_bytes();

        let wallet = MLDSA65Wallet::from_parts(public_bytes, encrypted_secret).map_err(|e| {
            ErrorDetection::ValidationError {
                message: format!("Failed to reconstruct Digital I.D. wallet from wallet file: {e}"),
                tx_id: None,
            }
        })?;

        if wallet.address != wallet_address {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Wallet file/address mismatch: requested {}, loaded {}",
                    wallet_address, wallet.address
                ),
                tx_id: None,
            });
        }

        Ok(wallet)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_digital_id_interactive(
        &mut self,
        opts: &NodeOpts,
        audit_dir: &Path,
        pdf_dir: &Path,
        json_logger: &JsonLogger,
        send_net_cmd: &mut dyn FnMut(NetCmd) -> Result<(), ErrorDetection>,
    ) -> Result<(), ErrorDetection> {
        const NFT_ID_BYTES: usize = 64;
        const NFT_ID_HEX_LEN: usize = 128;
        const CONTENT_HASH_HEX_LEN: usize = 128;

        println!();
        println!("{}", "🪪 Digital I.D".cyan());

        let confirmed = match Self::confirm_yes_no(
            &format!(
                "{} ",
                "Do you want to create a decentralized Digital Identification card? (yes/no):"
                    .yellow()
            ),
            "digital_id.confirm",
        ) {
            Ok(v) => v,
            Err(e) => {
                println!(
                    "{}",
                    format!("❌ Digital I.D. confirmation failed: {e:?}").red()
                );
                json_logger
                    .log_error_event("digital_id", "DigitalIdConfirmFailed", &format!("{e:?}"))
                    .ok();
                return Ok(());
            }
        };

        if !confirmed {
            println!(
                "{}",
                "↩️  Digital I.D. cancelled, returning to menu.".yellow()
            );
            return Ok(());
        }

        let understood = match Self::confirm_yes_no(
            &format!(
                "{} ",
                "This process is going to make a digital identification card using Remzar blockchain technology. Continue? (yes/no):".yellow()
            ),
            "digital_id.explain.confirm",
        ) {
            Ok(v) => v,
            Err(e) => {
                println!("{}", format!("❌ Digital I.D. explanation confirmation failed: {e:?}").red());
                json_logger
                    .log_error_event(
                        "digital_id",
                        "DigitalIdExplainConfirmFailed",
                        &format!("{e:?}"),
                    )
                    .ok();
                return Ok(());
            }
        };

        if !understood {
            println!(
                "{}",
                "↩️  Digital I.D. cancelled, returning to menu.".yellow()
            );
            return Ok(());
        }

        println!();
        println!(
            "{}",
            "Please enter all the fields correctly for correct authentication. Press Enter to leave a field blank."
                .cyan()
        );
        println!(
            "{}",
            "Birth is stored as entered. Example: 1985-04-22, 1888-44-55, or blank.".yellow()
        );

        let name = match Self::read_trimmed_prompt(
            "Name: ",
            "digital_id.name.read",
            GlobalConfiguration::MAX_INPUT_BYTES,
        ) {
            Ok(v) => v,
            Err(e) => {
                println!("{}", format!("❌ Failed to read Name: {e:?}").red());
                return Ok(());
            }
        };

        let birth = match Self::read_trimmed_prompt(
            "Birth: ",
            "digital_id.birth.read",
            GlobalConfiguration::MAX_INPUT_BYTES,
        ) {
            Ok(v) => v,
            Err(e) => {
                println!("{}", format!("❌ Failed to read Birth: {e:?}").red());
                return Ok(());
            }
        };

        let sex = match Self::read_trimmed_prompt(
            "Sex: ",
            "digital_id.sex.read",
            GlobalConfiguration::MAX_INPUT_BYTES,
        ) {
            Ok(v) => v,
            Err(e) => {
                println!("{}", format!("❌ Failed to read Sex: {e:?}").red());
                return Ok(());
            }
        };

        let height = match Self::read_trimmed_prompt(
            "Height: ",
            "digital_id.height.read",
            GlobalConfiguration::MAX_INPUT_BYTES,
        ) {
            Ok(v) => v,
            Err(e) => {
                println!("{}", format!("❌ Failed to read Height: {e:?}").red());
                return Ok(());
            }
        };

        let nationality = match Self::read_trimmed_prompt(
            "Nationality: ",
            "digital_id.nationality.read",
            GlobalConfiguration::MAX_INPUT_BYTES,
        ) {
            Ok(v) => v,
            Err(e) => {
                println!("{}", format!("❌ Failed to read Nationality: {e:?}").red());
                return Ok(());
            }
        };

        let country = match Self::read_trimmed_prompt(
            "Country: ",
            "digital_id.country.read",
            GlobalConfiguration::MAX_INPUT_BYTES,
        ) {
            Ok(v) => v,
            Err(e) => {
                println!("{}", format!("❌ Failed to read Country: {e:?}").red());
                return Ok(());
            }
        };

        let address = match Self::read_trimmed_prompt(
            "Address: ",
            "digital_id.address.read",
            GlobalConfiguration::MAX_INPUT_BYTES,
        ) {
            Ok(v) => v,
            Err(e) => {
                println!("{}", format!("❌ Failed to read Address: {e:?}").red());
                return Ok(());
            }
        };

        let job = match Self::read_trimmed_prompt(
            "Job: ",
            "digital_id.job.read",
            GlobalConfiguration::MAX_INPUT_BYTES,
        ) {
            Ok(v) => v,
            Err(e) => {
                println!("{}", format!("❌ Failed to read Job: {e:?}").red());
                return Ok(());
            }
        };

        let fields = match DigitalPassportFields::from_raw(
            name,
            birth,
            sex,
            height,
            nationality,
            country,
            address,
            job,
        ) {
            Ok(fields) => fields,
            Err(e) => {
                println!();
                println!("{}", "❌ Digital I.D. field validation failed.".red());
                println!("{}", format!("Details: {e:?}").red());
                println!(
                    "{}",
                    "No Digital I.D. was minted. No JSON/PDF/QR was created.".yellow()
                );

                json_logger
                    .log_error_event(
                        "digital_id",
                        "DigitalIdFieldValidationFailed",
                        &format!("{e:?}"),
                    )
                    .ok();

                return Ok(());
            }
        };

        println!();
        println!(
            "{}",
            "Enter wallet address for Digital I.D. authentication:".cyan()
        );

        let wallet_in = match Self::read_trimmed_prompt(
            "Wallet Address: ",
            "digital_id.wallet.read",
            GlobalConfiguration::MAX_INPUT_BYTES,
        ) {
            Ok(v) => v,
            Err(e) => {
                println!(
                    "{}",
                    format!("❌ Failed to read wallet address: {e:?}").red()
                );
                return Ok(());
            }
        };

        let wallet_address = match Self::canonicalize_wallet(&wallet_in, "Digital I.D.") {
            Ok(v) => v,
            Err(e) => {
                println!("{}", "❌ Invalid Digital I.D. wallet address.".red());
                println!("{}", format!("Details: {e:?}").red());

                json_logger
                    .log_error_event(
                        "digital_id",
                        "DigitalIdWalletAddressInvalid",
                        &format!("{e:?}"),
                    )
                    .ok();

                return Ok(());
            }
        };

        let mut passphrase = match Password::new()
            .with_prompt("🔒 Enter passphrase for wallet authentication")
            .allow_empty_password(false)
            .interact()
        {
            Ok(pass) => pass,
            Err(e) => {
                let msg = format!("Failed to read Digital I.D. wallet passphrase: {e}");
                println!("{}", format!("❌ {msg}").red());

                json_logger
                    .log_error_event("digital_id", "DigitalIdPassphraseReadFailed", &msg)
                    .ok();

                return Ok(());
            }
        };

        let mut confirm_passphrase = match Password::new()
            .with_prompt("🔒 Confirm wallet passphrase")
            .allow_empty_password(false)
            .interact()
        {
            Ok(pass) => pass,
            Err(e) => {
                passphrase.zeroize();

                let msg =
                    format!("Failed to read Digital I.D. wallet passphrase confirmation: {e}");
                println!("{}", format!("❌ {msg}").red());

                json_logger
                    .log_error_event("digital_id", "DigitalIdPassphraseConfirmReadFailed", &msg)
                    .ok();

                return Ok(());
            }
        };

        if passphrase != confirm_passphrase {
            passphrase.zeroize();
            confirm_passphrase.zeroize();

            println!("{}", "❌ Digital I.D. passphrases do not match.".red());
            println!(
                "{}",
                "No Digital I.D. was minted. No JSON/PDF/QR was created.".yellow()
            );

            json_logger
                .log_error_event(
                    "digital_id",
                    "DigitalIdPassphraseMismatch",
                    "Digital I.D. passphrases do not match",
                )
                .ok();

            return Ok(());
        }

        let wallet = match Self::load_wallet_for_digital_id(opts, &wallet_address, &passphrase) {
            Ok(wallet) => wallet,
            Err(e) => {
                passphrase.zeroize();
                confirm_passphrase.zeroize();

                println!("{}", "❌ Digital I.D. wallet authentication failed.".red());
                println!("{}", format!("Details: {e:?}").red());
                println!(
                    "{}",
                    "No Digital I.D. was minted. No JSON/PDF/QR was created.".yellow()
                );

                json_logger
                    .log_error_event("digital_id", "DigitalIdWalletLoadFailed", &format!("{e:?}"))
                    .ok();

                return Ok(());
            }
        };

        let mut nft_id = [0u8; NFT_ID_BYTES];
        rand::rng().fill(&mut nft_id);

        let nft_id_hex = hex::encode(nft_id);
        debug_assert_eq!(nft_id_hex.len(), NFT_ID_HEX_LEN);

        let passport = match DigitalPassport::new_signed(
            nft_id_hex.clone(),
            wallet_address,
            &wallet,
            passphrase,
            confirm_passphrase,
            fields,
        ) {
            Ok(passport) => passport,
            Err(e) => {
                println!(
                    "{}",
                    "❌ Failed to create signed Digital I.D. passport.".red()
                );
                println!("{}", format!("Details: {e:?}").red());
                println!(
                    "{}",
                    "No Digital I.D. was minted. No JSON/PDF/QR was created.".yellow()
                );

                json_logger
                    .log_error_event(
                        "digital_id",
                        "DigitalIdPassportCreateFailed",
                        &format!("{e:?}"),
                    )
                    .ok();

                return Ok(());
            }
        };

        let content_bytes = match passport.content_bytes_for_nft() {
            Ok(bytes) => bytes,
            Err(e) => {
                println!(
                    "{}",
                    "❌ Failed to build Digital I.D. NFT proof bytes.".red()
                );
                println!("{}", format!("Details: {e:?}").red());
                println!(
                    "{}",
                    "No Digital I.D. was minted. No JSON/PDF/QR was created.".yellow()
                );

                json_logger
                    .log_error_event(
                        "digital_id",
                        "DigitalIdContentBytesFailed",
                        &format!("{e:?}"),
                    )
                    .ok();

                return Ok(());
            }
        };

        let tx = NftMintTx::from_content_bytes(
            nft_id,
            passport.nft_title(),
            passport.nft_description_redacted(),
            &content_bytes,
        );

        let content_hash_hex = hex::encode(tx.content_hash);
        debug_assert_eq!(content_hash_hex.len(), CONTENT_HASH_HEX_LEN);

        let local_expected = RemzarHash::compute_bytes_hash_hex(&content_bytes);
        if local_expected != content_hash_hex {
            let msg = format!(
                "Digital I.D. content hash mismatch: NftMintTx hash != RemzarHash hash (tx={}, local={})",
                content_hash_hex, local_expected
            );

            println!("{}", format!("❌ {msg}").red());
            println!(
                "{}",
                "No Digital I.D. was minted. No JSON/PDF/QR was created.".yellow()
            );

            json_logger
                .log_error_event("digital_id", "DigitalIdContentHashMismatch", &msg)
                .ok();

            return Ok(());
        }

        if let Err(e) = send_net_cmd(NetCmd::SendTxKind(TxKind::NftMint(tx))) {
            println!("{}", "❌ Failed to submit Digital I.D. NftMintTx.".red());
            println!("{}", format!("Details: {e:?}").red());
            println!(
                "{}",
                "No JSON/PDF/QR was written because the NFT mint was not submitted.".yellow()
            );

            json_logger
                .log_error_event(
                    "digital_id",
                    "DigitalIdNftMintSubmitFailed",
                    &format!("{e:?}"),
                )
                .ok();

            return Ok(());
        }

        let files = match passport.write_receipt_files(audit_dir, pdf_dir) {
            Ok(files) => files,
            Err(e) => {
                println!(
                    "{}",
                    "⚠️ Digital I.D. NftMintTx was submitted, but receipt writing failed.".yellow()
                );
                println!("{}", format!("Details: {e:?}").red());

                json_logger
                    .log_error_event(
                        "digital_id",
                        "DigitalIdReceiptWriteFailed",
                        &format!("{e:?}"),
                    )
                    .ok();

                return Ok(());
            }
        };

        println!();
        println!(
            "{}",
            "✅ Digital I.D. mint transaction submitted to mempool / network.".green()
        );
        println!("  NFT ID:                 {}", nft_id_hex);
        println!("  Type (kind):            {}", passport.kind);
        println!("  Schema:                 {}", passport.schema);
        println!("  Wallet address:         {}", passport.wallet_address);
        println!(
            "  Digital fingerprint:    {}",
            passport.digital_fingerprint_hex
        );
        println!("  Content hash:           {}", content_hash_hex);
        println!("  Created UTC:            {}", passport.created_at_utc);
        println!("  JSON certificate:       {}", files.json_path.display());
        println!("  PDF certificate:        {}", files.pdf_path.display());
        println!("  QR code PNG:            {}", files.qr_png_path.display());

        Ok(())
    }

    pub fn verify_certificate_interactive(
        &mut self,
        db_manager: &Arc<RockDBManager>,
        _json_logger: &JsonLogger,
    ) -> Result<(), ErrorDetection> {
        const NFT_ID_HEX_LEN: usize = 128;
        const NFT_ID_BYTES: usize = 64;
        const MAX_JSON_BYTES: u64 = 5 * 1024 * 1024;
        const MAX_FILE_BYTES: u64 = 25 * 1024 * 1024;

        println!();
        println!(
            "{}",
            "🔎 Verify certificate / NFT / RWA / Digital I.D. against chain".cyan()
        );

        println!(
            "{}",
            "Enter path to certificate JSON, RWA JSON, or Digital I.D. JSON:".cyan()
        );
        println!("{}", "Examples:".yellow());
        println!("  data/nft.certificate/certificate_<id>.json");
        println!("  data/rwa.certificate/rwa_certificate_<id>.json");
        println!("  data/digital_id/digital_id_<id>.json");
        print!("JSON path: ");
        Self::flush_stdout("verify.cert_path.flush")?;

        let cert_path = Self::read_line_capped(
            "verify.cert_path.read",
            GlobalConfiguration::MAX_INPUT_BYTES,
        )?;
        let cert_path = cert_path.trim().to_string();

        if cert_path.is_empty() {
            return Err(ErrorDetection::ValidationError {
                message: "Certificate / RWA / Digital I.D. JSON path cannot be empty".into(),
                tx_id: None,
            });
        }

        let meta = fs::metadata(&cert_path).map_err(|e| ErrorDetection::IoError {
            message: format!("Failed to stat JSON {cert_path}: {e}"),
            code: e.raw_os_error(),
            source: Some(Box::new(e)),
        })?;

        if !meta.is_file() || meta.len() == 0 || meta.len() > MAX_JSON_BYTES {
            return Err(ErrorDetection::ValidationError {
                message: format!("JSON invalid or too large: {}", cert_path),
                tx_id: None,
            });
        }

        let json_str = fs::read_to_string(&cert_path).map_err(|e| ErrorDetection::IoError {
            message: format!("Failed to read JSON {cert_path}: {e}"),
            code: e.raw_os_error(),
            source: Some(Box::new(e)),
        })?;

        // -----------------------------------------------------------------
        // First try the normal NFT / certificate receipt format.
        // -----------------------------------------------------------------
        let standard_parse_error = match serde_json::from_str::<CertificateReceipt>(&json_str) {
            Ok(receipt) => {
                receipt.validate()?;

                println!();
                println!("Loaded certificate:");
                println!("  NFT ID:        {}", receipt.nft_id_hex);
                println!("  Owner wallet:  {}", receipt.owner_wallet);
                println!(
                    "  File:          {} ({} bytes)",
                    receipt.file_name, receipt.file_size_bytes
                );
                println!("  Content hash:  {}", receipt.content_hash_hex);
                println!("  Kind / schema: {} / {}", receipt.kind, receipt.schema);

                if receipt.nft_id_hex.len() != NFT_ID_HEX_LEN {
                    return Err(ErrorDetection::ValidationError {
                        message: format!(
                            "Invalid nft_id_hex length: expected {} hex chars, got {}",
                            NFT_ID_HEX_LEN,
                            receipt.nft_id_hex.len()
                        ),
                        tx_id: None,
                    });
                }

                let nft_id_bytes = hex::decode(receipt.nft_id_hex.trim()).map_err(|e| {
                    ErrorDetection::ValidationError {
                        message: format!("Invalid nft_id_hex in certificate (not hex): {e}"),
                        tx_id: None,
                    }
                })?;

                if nft_id_bytes.len() != NFT_ID_BYTES {
                    return Err(ErrorDetection::ValidationError {
                        message: format!(
                            "Invalid nft_id_hex length: expected {} bytes, got {}",
                            NFT_ID_BYTES,
                            nft_id_bytes.len()
                        ),
                        tx_id: None,
                    });
                }

                let mut nft_id = [0u8; NFT_ID_BYTES];
                nft_id.copy_from_slice(&nft_id_bytes);

                let maybe_record = load_nft_record(db_manager, &nft_id)?;
                let mut all_ok = true;

                match maybe_record {
                    None => {
                        println!();
                        println!(
                            "{}",
                            "❌ No on-chain NftRecord found for this nft_id on this node.".red()
                        );
                        all_ok = false;
                    }
                    Some(record) => {
                        let onchain_hash_hex = hex::encode(record.content_hash);
                        let onchain_owner = &record.owner_wallet;

                        println!();
                        println!("{}", "On-chain NFT record:".cyan());
                        println!("  Minted height: {}", record.minted_height);
                        println!("  Minted time:   {}", record.minted_time);
                        println!("  Creator:       {}", record.creator_wallet);
                        println!("  Owner:         {}", onchain_owner);
                        println!("  Content hash:  {}", onchain_hash_hex);

                        if receipt.owner_wallet == *onchain_owner {
                            println!(
                                "{}",
                                "  ✅ Owner wallet matches between certificate and chain.".green()
                            );
                        } else {
                            println!(
                                "{}",
                                "  ❌ Owner wallet mismatch between certificate and chain!".red()
                            );
                            println!("     Cert:  {}", receipt.owner_wallet);
                            println!("     Chain: {}", onchain_owner);
                            all_ok = false;
                        }

                        if receipt.content_hash_hex == onchain_hash_hex {
                            println!(
                                "{}",
                                "  ✅ content_hash matches between certificate and chain.".green()
                            );
                        } else {
                            println!(
                                "{}",
                                "  ❌ content_hash mismatch between certificate and chain!".red()
                            );
                            println!("     Cert:  {}", receipt.content_hash_hex);
                            println!("     Chain: {}", onchain_hash_hex);
                            all_ok = false;
                        }

                        println!();
                        println!(
                            "{}",
                            "Optional: verify against a local file (enter path or press Enter to skip):"
                                .cyan()
                        );
                        print!("Original file path [default:{}]: ", receipt.file_name);
                        Self::flush_stdout("verify.file_path.flush")?;

                        let file_path2 = Self::read_line_capped(
                            "verify.file_path.read",
                            GlobalConfiguration::MAX_INPUT_BYTES,
                        )?;
                        let file_path2 = file_path2.trim().to_string();

                        if !file_path2.is_empty() {
                            let meta2 =
                                fs::metadata(&file_path2).map_err(|e| ErrorDetection::IoError {
                                    message: format!(
                                        "Failed to stat original file {}: {e}",
                                        file_path2
                                    ),
                                    code: e.raw_os_error(),
                                    source: Some(Box::new(e)),
                                })?;

                            if !meta2.is_file() || meta2.len() == 0 || meta2.len() > MAX_FILE_BYTES
                            {
                                return Err(ErrorDetection::ValidationError {
                                    message: format!(
                                        "Original file invalid or too large: {}",
                                        file_path2
                                    ),
                                    tx_id: None,
                                });
                            }

                            let file_bytes =
                                fs::read(&file_path2).map_err(|e| ErrorDetection::IoError {
                                    message: format!(
                                        "Failed to read original file {}: {e}",
                                        file_path2
                                    ),
                                    code: e.raw_os_error(),
                                    source: Some(Box::new(e)),
                                })?;

                            let file_hash_hex = RemzarHash::compute_bytes_hash_hex(&file_bytes);
                            println!("  File hash: {}", file_hash_hex);

                            let mut file_ok = true;

                            if file_hash_hex != receipt.content_hash_hex {
                                println!(
                                    "{}",
                                    "  ❌ File hash != certificate content_hash_hex.".red()
                                );
                                file_ok = false;
                            }

                            if file_hash_hex != onchain_hash_hex {
                                println!("{}", "  ❌ File hash != on-chain content_hash.".red());
                                file_ok = false;
                            }

                            if file_ok {
                                println!(
                                    "{}",
                                    "  ✅ Local file hash matches both certificate and chain."
                                        .green()
                                );
                            } else {
                                all_ok = false;
                            }
                        } else {
                            println!("{}", "  (Skipping local file hash check.)".yellow());
                        }
                    }
                }

                println!();
                if all_ok {
                    println!(
                        "{}",
                        "✅ Verification result: certificate is consistent with chain (and file, if provided)."
                            .green()
                    );
                } else {
                    println!(
                        "{}",
                        "❌ Verification result: one or more mismatches detected. See details above."
                            .red()
                    );
                }

                return Ok(());
            }
            Err(e) => e.to_string(),
        };

        let rwa_parse_error = match serde_json::from_str::<RwaAssetCertificate>(&json_str) {
            Ok(certificate) => {
                certificate.validate()?;

                let rwa_id_hex = certificate.certificate_id_hex();

                if rwa_id_hex.len() != NFT_ID_HEX_LEN {
                    return Err(ErrorDetection::ValidationError {
                        message: format!(
                            "Invalid RWA certificate_id length: expected {} hex chars, got {}",
                            NFT_ID_HEX_LEN,
                            rwa_id_hex.len()
                        ),
                        tx_id: None,
                    });
                }

                let nft_id = certificate.certificate_id.0;
                let recomputed_metadata_hash_hex = certificate.recompute_metadata_hash()?.to_hex();
                let certificate_metadata_hash_hex = certificate.metadata_hash_hex();

                let rwa_payload_bytes = certificate.to_nft_content_bytes()?;
                let recomputed_content_hash_hex =
                    RemzarHash::compute_bytes_hash_hex(&rwa_payload_bytes);
                let model_content_hash_hex = certificate.content_hash_hex()?;

                println!();
                println!("{}", "Loaded RWA certificate:".cyan());
                println!("  NFT / RWA ID:          {}", rwa_id_hex);
                println!(
                    "  Kind / schema:         {} / {}",
                    certificate.kind, certificate.schema
                );
                println!("  Issuer wallet:         {}", certificate.issuer_wallet);
                println!("  Owner wallet:          {}", certificate.owner_wallet);
                println!("  Status:                {:?}", certificate.status);
                println!(
                    "  Asset class:           {:?}",
                    certificate.core.asset_class
                );
                println!("  Asset name:            {}", certificate.core.asset_name);
                println!(
                    "  Legal jurisdiction:    {}",
                    certificate.legal.legal_jurisdiction
                );
                println!(
                    "  Valuation USD cents:   {}",
                    certificate.core.asset_valuation_usd_cents
                );
                println!("  Yield bps:             {}", certificate.core.yield_bps);
                println!("  Total supply:          {}", certificate.core.total_supply);
                println!("  Decimals:              {}", certificate.core.decimals);
                println!("  Metadata hash:         {}", certificate_metadata_hash_hex);
                println!("  Recomputed metadata:   {}", recomputed_metadata_hash_hex);
                println!("  Recomputed content:    {}", recomputed_content_hash_hex);

                let mut all_ok = true;

                if certificate.kind == RWA_KIND && certificate.schema == RWA_SCHEMA {
                    println!(
                        "{}",
                        "  ✅ RWA kind/schema match expected Remzar RWA constants.".green()
                    );
                } else {
                    println!(
                        "{}",
                        "  ❌ RWA kind/schema mismatch against expected Remzar RWA constants."
                            .red()
                    );
                    println!("     Expected: {} / {}", RWA_KIND, RWA_SCHEMA);
                    println!(
                        "     Found:    {} / {}",
                        certificate.kind, certificate.schema
                    );
                    all_ok = false;
                }

                if certificate_metadata_hash_hex == recomputed_metadata_hash_hex {
                    println!("{}", "  ✅ RWA metadata_hash recomputes correctly.".green());
                } else {
                    println!(
                        "{}",
                        "  ❌ RWA metadata_hash does not recompute correctly.".red()
                    );
                    println!("     Certificate: {}", certificate_metadata_hash_hex);
                    println!("     Recomputed:  {}", recomputed_metadata_hash_hex);
                    all_ok = false;
                }

                if model_content_hash_hex == recomputed_content_hash_hex {
                    println!(
                        "{}",
                        "  ✅ RWA NFT content hash recomputes consistently.".green()
                    );
                } else {
                    println!(
                        "{}",
                        "  ❌ RWA NFT content hash mismatch inside local verification.".red()
                    );
                    println!("     Model method: {}", model_content_hash_hex);
                    println!("     Local hash:   {}", recomputed_content_hash_hex);
                    all_ok = false;
                }

                let maybe_record = load_nft_record(db_manager, &nft_id)?;

                match maybe_record {
                    None => {
                        println!();
                        println!(
                            "{}",
                            "❌ No on-chain NftRecord found for this RWA certificate_id / NFT ID on this node."
                                .red()
                        );
                        all_ok = false;
                    }
                    Some(record) => {
                        let onchain_nft_id_hex = hex::encode(record.nft_id);
                        let onchain_hash_hex = hex::encode(record.content_hash);

                        println!();
                        println!("{}", "On-chain NFT record for RWA:".cyan());
                        println!("  NFT ID:        {}", onchain_nft_id_hex);
                        println!("  Minted height: {}", record.minted_height);
                        println!("  Minted time:   {}", record.minted_time);
                        println!("  Creator:       {}", record.creator_wallet);
                        println!("  Owner:         {}", record.owner_wallet);
                        println!("  Title:         {}", record.title);
                        println!("  Description:   {}", record.description);
                        println!("  Content hash:  {}", onchain_hash_hex);

                        if onchain_nft_id_hex == rwa_id_hex {
                            println!(
                                "{}",
                                "  ✅ RWA certificate_id matches the on-chain NFT ID.".green()
                            );
                        } else {
                            println!(
                                "{}",
                                "  ❌ RWA certificate_id does not match the on-chain NFT ID.".red()
                            );
                            println!("     RWA JSON: {}", rwa_id_hex);
                            println!("     Chain:    {}", onchain_nft_id_hex);
                            all_ok = false;
                        }

                        if record.owner_wallet == certificate.owner_wallet {
                            println!(
                                "{}",
                                "  ✅ RWA owner wallet matches the current on-chain owner wallet."
                                    .green()
                            );
                        } else {
                            println!(
                                "{}",
                                "  ❌ RWA owner wallet mismatch between RWA JSON and chain.".red()
                            );
                            println!("     RWA JSON owner: {}", certificate.owner_wallet);
                            println!("     Chain owner:    {}", record.owner_wallet);
                            all_ok = false;
                        }

                        let expected_title = certificate.nft_title();
                        if record.title == expected_title {
                            println!(
                                "{}",
                                "  ✅ RWA NFT title matches the on-chain NFT title.".green()
                            );
                        } else {
                            println!(
                                "{}",
                                "  ❌ RWA NFT title mismatch between RWA JSON and chain.".red()
                            );
                            println!("     Expected: {}", expected_title);
                            println!("     Chain:    {}", record.title);
                            all_ok = false;
                        }

                        let expected_description = certificate.nft_description();
                        if record.description == expected_description {
                            println!(
                                "{}",
                                "  ✅ RWA NFT description matches the on-chain NFT description."
                                    .green()
                            );
                        } else {
                            println!(
                                "{}",
                                "  ❌ RWA NFT description mismatch between RWA JSON and chain."
                                    .red()
                            );
                            println!("     Expected: {}", expected_description);
                            println!("     Chain:    {}", record.description);
                            all_ok = false;
                        }

                        println!();
                        println!("{}", "RWA payload hash check:".cyan());
                        println!(
                            "  Recomputed RWA NFT payload hash: {}",
                            recomputed_content_hash_hex
                        );
                        println!(
                            "  RWA model content hash:          {}",
                            model_content_hash_hex
                        );
                        println!("  On-chain content hash:           {}", onchain_hash_hex);

                        if recomputed_content_hash_hex == onchain_hash_hex
                            && model_content_hash_hex == onchain_hash_hex
                        {
                            println!(
                                "{}",
                                "  ✅ RWA certificate payload hash matches the on-chain NFT content hash."
                                    .green()
                            );
                        } else {
                            println!(
                                "{}",
                                "  ❌ RWA certificate payload hash does not match the on-chain NFT content hash."
                                    .red()
                            );
                            all_ok = false;
                        }

                        println!();
                        println!(
                            "{}",
                            "Optional: verify against the local RWA NFT payload file / .postcard file (enter path or press Enter to skip):"
                                .cyan()
                        );
                        println!(
                            "{}",
                            "Note: this optional check is for the exact minted payload bytes, not the pretty audit JSON file."
                                .yellow()
                        );
                        print!(
                            "RWA payload path [default:rwa_certificate_{}.postcard]: ",
                            rwa_id_hex
                        );
                        Self::flush_stdout("verify.rwa_payload_path.flush")?;

                        let payload_path = Self::read_line_capped(
                            "verify.rwa_payload_path.read",
                            GlobalConfiguration::MAX_INPUT_BYTES,
                        )?;
                        let payload_path = payload_path.trim().to_string();

                        if !payload_path.is_empty() {
                            let payload_meta = fs::metadata(&payload_path).map_err(|e| {
                                ErrorDetection::IoError {
                                    message: format!(
                                        "Failed to stat RWA payload file {}: {e}",
                                        payload_path
                                    ),
                                    code: e.raw_os_error(),
                                    source: Some(Box::new(e)),
                                }
                            })?;

                            if !payload_meta.is_file()
                                || payload_meta.len() == 0
                                || payload_meta.len() > MAX_FILE_BYTES
                            {
                                return Err(ErrorDetection::ValidationError {
                                    message: format!(
                                        "RWA payload file invalid or too large: {}",
                                        payload_path
                                    ),
                                    tx_id: None,
                                });
                            }

                            let payload_file_bytes =
                                fs::read(&payload_path).map_err(|e| ErrorDetection::IoError {
                                    message: format!(
                                        "Failed to read RWA payload file {}: {e}",
                                        payload_path
                                    ),
                                    code: e.raw_os_error(),
                                    source: Some(Box::new(e)),
                                })?;

                            let payload_file_hash_hex =
                                RemzarHash::compute_bytes_hash_hex(&payload_file_bytes);

                            println!("  RWA payload file hash: {}", payload_file_hash_hex);

                            let mut payload_file_ok = true;

                            if payload_file_hash_hex != recomputed_content_hash_hex {
                                println!(
                                    "{}",
                                    "  ❌ RWA payload file hash != recomputed RWA content hash."
                                        .red()
                                );
                                payload_file_ok = false;
                            }

                            if payload_file_hash_hex != onchain_hash_hex {
                                println!(
                                    "{}",
                                    "  ❌ RWA payload file hash != on-chain content_hash.".red()
                                );
                                payload_file_ok = false;
                            }

                            if payload_file_ok {
                                println!(
                                    "{}",
                                    "  ✅ Local RWA payload file hash matches both RWA JSON and chain."
                                        .green()
                                );
                            } else {
                                all_ok = false;
                            }
                        } else {
                            println!(
                                "{}",
                                "  (Skipping local RWA payload file hash check.)".yellow()
                            );
                        }
                    }
                }

                println!();
                if all_ok {
                    println!(
                        "{}",
                        "✅ Verification result: RWA certificate is valid and proven on-chain."
                            .green()
                    );
                } else {
                    println!(
                        "{}",
                        "❌ Verification result: RWA JSON parsed and validated, but one or more chain checks failed."
                            .red()
                    );
                }

                return Ok(());
            }
            Err(e) => e.to_string(),
        };

        // -----------------------------------------------------------------
        // If it was not a normal certificate receipt or RWA certificate,
        // try Digital I.D.
        // Digital I.D. receipts are different JSON, but they are still minted
        // as NftMintTx and can be proven against the on-chain NftRecord.
        // -----------------------------------------------------------------
        let passport: DigitalPassport = serde_json::from_str(&json_str).map_err(|digital_err| {
            ErrorDetection::SerializationError {
                details: format!(
                    "JSON is not a valid CertificateReceipt, RwaAssetCertificate, or DigitalPassport. \
                    CertificateReceipt parse error: {standard_parse_error}. \
                    RwaAssetCertificate parse error: {rwa_parse_error}. \
                    DigitalPassport parse error: {digital_err}"
                ),
            }
        })?;

        passport.validate()?;

        println!();
        println!("{}", "Loaded Digital I.D.:".cyan());
        println!("  Passport / NFT ID:       {}", passport.passport_id_hex);
        println!(
            "  Kind / schema:           {} / {}",
            passport.kind, passport.schema
        );
        println!("  Wallet address:          {}", passport.wallet_address);
        println!(
            "  Wallet public key hex:   {}",
            passport.wallet_public_key_hex
        );
        println!(
            "  Digital fingerprint:     {}",
            passport.digital_fingerprint_hex
        );
        println!("  Created UTC:             {}", passport.created_at_utc);
        println!(
            "{}",
            "  ✅ Digital I.D. JSON structure, fingerprint, wallet/public-key binding, and ML-DSA signature are valid."
                .green()
        );

        let passport_id_hex = passport.passport_id_hex.trim();

        if passport_id_hex.len() != NFT_ID_HEX_LEN {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Invalid passport_id_hex length: expected {} hex chars, got {}",
                    NFT_ID_HEX_LEN,
                    passport_id_hex.len()
                ),
                tx_id: None,
            });
        }

        let nft_id_bytes =
            hex::decode(passport_id_hex).map_err(|e| ErrorDetection::ValidationError {
                message: format!("Invalid passport_id_hex in Digital I.D. (not hex): {e}"),
                tx_id: None,
            })?;

        if nft_id_bytes.len() != NFT_ID_BYTES {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Invalid passport_id_hex length: expected {} bytes, got {}",
                    NFT_ID_BYTES,
                    nft_id_bytes.len()
                ),
                tx_id: None,
            });
        }

        let mut nft_id = [0u8; NFT_ID_BYTES];
        nft_id.copy_from_slice(&nft_id_bytes);

        let maybe_record = load_nft_record(db_manager, &nft_id)?;
        let mut all_ok = true;

        match maybe_record {
            None => {
                println!();
                println!(
                    "{}",
                    "❌ No on-chain NftRecord found for this Digital I.D. passport_id / NFT ID on this node."
                        .red()
                );
                all_ok = false;
            }
            Some(record) => {
                let onchain_hash_hex = hex::encode(record.content_hash);
                let onchain_nft_id_hex = hex::encode(record.nft_id);

                println!();
                println!("{}", "On-chain NFT record for Digital I.D.:".cyan());
                println!("  NFT ID:        {}", onchain_nft_id_hex);
                println!("  Minted height: {}", record.minted_height);
                println!("  Minted time:   {}", record.minted_time);
                println!("  Creator:       {}", record.creator_wallet);
                println!("  Owner:         {}", record.owner_wallet);
                println!("  Title:         {}", record.title);
                println!("  Description:   {}", record.description);
                println!("  Content hash:  {}", onchain_hash_hex);

                if onchain_nft_id_hex == passport.passport_id_hex {
                    println!(
                        "{}",
                        "  ✅ Digital I.D. passport_id matches the on-chain NFT ID.".green()
                    );
                } else {
                    println!(
                        "{}",
                        "  ❌ Digital I.D. passport_id does not match on-chain NFT ID.".red()
                    );
                    println!("     Digital I.D.: {}", passport.passport_id_hex);
                    println!("     Chain:        {}", onchain_nft_id_hex);
                    all_ok = false;
                }

                if record.creator_wallet == passport.wallet_address {
                    println!(
                        "{}",
                        "  ✅ Digital I.D. wallet matches the on-chain creator wallet.".green()
                    );
                } else {
                    println!(
                        "{}",
                        "  ⚠️ Digital I.D. wallet does not match the on-chain creator wallet."
                            .yellow()
                    );
                    println!("     Digital I.D. wallet: {}", passport.wallet_address);
                    println!("     Chain creator:       {}", record.creator_wallet);
                    println!(
                        "{}",
                        "     This is only a warning. The Digital I.D. proof is verified by signature + on-chain content hash."
                            .yellow()
                    );
                }

                if record.owner_wallet == passport.wallet_address {
                    println!(
                        "{}",
                        "  ✅ Digital I.D. wallet matches the current on-chain owner wallet."
                            .green()
                    );
                } else {
                    println!(
                        "{}",
                        "  ⚠️ Digital I.D. wallet does not match the current on-chain owner wallet.".yellow()
                    );
                    println!("     Digital I.D. wallet: {}", passport.wallet_address);
                    println!("     Chain owner:         {}", record.owner_wallet);
                    println!(
                        "{}",
                        "     This is only a warning. The Digital I.D. may still be valid if the proof hash matches the chain."
                            .yellow()
                    );
                }

                let proof_bytes = passport.content_bytes_for_nft()?;
                let local_hash_hex = RemzarHash::compute_bytes_hash_hex(&proof_bytes);

                println!();
                println!("{}", "Digital I.D. proof hash check:".cyan());
                println!("  Recomputed proof hash: {}", local_hash_hex);
                println!("  On-chain content hash: {}", onchain_hash_hex);

                if local_hash_hex == onchain_hash_hex {
                    println!(
                        "{}",
                        "  ✅ Digital I.D. proof payload hash matches the on-chain NFT content hash."
                            .green()
                    );
                } else {
                    println!(
                        "{}",
                        "  ❌ Digital I.D. proof payload hash does not match the on-chain NFT content hash."
                            .red()
                    );
                    all_ok = false;
                }
            }
        }

        println!();
        if all_ok {
            println!(
                "{}",
                "✅ Verification result: Digital I.D. is valid, signed, and proven on-chain."
                    .green()
            );
        } else {
            println!(
                "{}",
                "❌ Verification result: Digital I.D. JSON is valid, but one or more chain checks failed."
                    .red()
            );
        }

        Ok(())
    }

    pub fn export_certificate_interactive(
        &mut self,
        db_manager: &Arc<RockDBManager>,
        audit_dir: &Path,
        pdf_dir: &Path,
        json_logger: &JsonLogger,
    ) -> Result<(), ErrorDetection> {
        const NFT_ID_HEX_LEN: usize = 128;
        const NFT_ID_BYTES: usize = 64;

        println!();
        println!("{}", "📤 Export certificate / NFT from chain".cyan());
        println!(
            "{}",
            "Enter NFT ID (64-byte hex, as printed in logs/certificates):".cyan()
        );
        print!("NFT ID (hex): ");
        Self::flush_stdout("export.nft_id.flush")?;

        let nft_id_hex =
            Self::read_line_capped("export.nft_id.read", GlobalConfiguration::MAX_INPUT_BYTES)?;
        let nft_id_hex = nft_id_hex.trim().to_string();

        if nft_id_hex.len() != NFT_ID_HEX_LEN {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Invalid NFT ID length: expected {} hex chars, got {}",
                    NFT_ID_HEX_LEN,
                    nft_id_hex.len()
                ),
                tx_id: None,
            });
        }

        let nft_id_bytes =
            hex::decode(&nft_id_hex).map_err(|e| ErrorDetection::ValidationError {
                message: format!("Invalid NFT ID hex (not hex): {e}"),
                tx_id: None,
            })?;

        if nft_id_bytes.len() != NFT_ID_BYTES {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Invalid NFT ID length: expected {} bytes, got {}",
                    NFT_ID_BYTES,
                    nft_id_bytes.len()
                ),
                tx_id: None,
            });
        }

        let mut nft_id = [0u8; NFT_ID_BYTES];
        nft_id.copy_from_slice(&nft_id_bytes);

        let record = match load_nft_record(db_manager, &nft_id)? {
            Some(r) => r,
            None => {
                let msg = format!(
                    "No on-chain NftRecord found for nft_id {} on this node.",
                    nft_id_hex
                );
                println!("{}", format!("❌ {msg}").red());
                json_logger
                    .log_error_event("nft", "ExportNftNotFound", &msg)
                    .ok();
                return Err(ErrorDetection::ValidationError {
                    message: msg,
                    tx_id: None,
                });
            }
        };

        let receipt = CertificateReceipt {
            nft_id_hex,
            owner_wallet: record.owner_wallet.clone(),
            file_name: "unknown_from_chain".to_string(),
            file_size_bytes: 0,
            content_hash_hex: hex::encode(record.content_hash),
            title: format!("Recovered NFT {}", hex::encode(record.nft_id)),
            description: format!(
                "Recovered from chain. Minted height: {} | Minted time (unix): {} | Creator: {} | Owner: {}",
                record.minted_height,
                record.minted_time,
                record.creator_wallet,
                record.owner_wallet
            ),
            created_at_utc: Self::runtime_utc_timestamp()?,
            edition: None,
            kind: "ExportedFromChain".to_string(),
            schema: "export-v1".to_string(),
        };

        receipt.validate()?;
        self.write_certificate_receipt_files(audit_dir, pdf_dir, &receipt)?;

        println!();
        println!(
            "{}",
            "✅ Export complete. JSON/PDF certificate reconstructed from chain.".green()
        );

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn transfer_certificate_interactive(
        &mut self,
        _opts: &NodeOpts,
        _db_manager: &Arc<RockDBManager>,
        audit_dir: &Path,
        pdf_dir: &Path,
        json_logger: &JsonLogger,
        send_net_cmd: &mut dyn FnMut(NetCmd) -> Result<(), ErrorDetection>,
    ) -> Result<(), ErrorDetection> {
        const NFT_ID_HEX_LEN: usize = 128;
        const NFT_ID_BYTES: usize = 64;
        const MAX_JSON_BYTES: u64 = 5 * 1024 * 1024;

        println!();
        println!(
            "{}",
            "🔁 Transfer certificate / NFT to another wallet".cyan()
        );

        let confirmed = Self::confirm_yes_no(
            &format!(
                "{} ",
                "Do you want to transfer a certificate / NFT? (yes/no):".yellow()
            ),
            "transfer.confirm",
        )?;
        if !confirmed {
            println!("{}", "↩️  Transfer cancelled, returning to menu.".yellow());
            return Ok(());
        }

        println!();
        println!(
            "{}",
            "Enter destination wallet address (new owner, 'r' + 128 lowercase hex):".cyan()
        );
        print!("New owner wallet: ");
        Self::flush_stdout("transfer.new_owner.flush")?;

        let new_owner = Self::read_line_capped(
            "transfer.new_owner.read",
            GlobalConfiguration::MAX_INPUT_BYTES,
        )?;
        let new_owner = Self::canonicalize_wallet(new_owner.trim(), "Destination")?;

        if let Err(e) = RegisterNodeTx::new(new_owner.clone()) {
            let msg = format!("Destination wallet is not a valid Remzar address: {e:?}");
            json_logger
                .log_error_event("nft", "TransferOwnerWalletInvalid", &msg)
                .ok();
            return Err(ErrorDetection::ValidationError {
                message: msg,
                tx_id: None,
            });
        }

        println!();
        println!("{}", "Enter path to existing certificate JSON (e.g. data/nft.certificate/certificate_<id>.json):".cyan());
        print!("Certificate JSON path: ");
        Self::flush_stdout("transfer.cert_path.flush")?;

        let cert_path = Self::read_line_capped(
            "transfer.cert_path.read",
            GlobalConfiguration::MAX_INPUT_BYTES,
        )?;
        let cert_path = cert_path.trim().to_string();

        let meta = fs::metadata(&cert_path).map_err(|e| ErrorDetection::IoError {
            message: format!("Failed to stat certificate JSON {cert_path}: {e}"),
            code: e.raw_os_error(),
            source: Some(Box::new(e)),
        })?;

        if !meta.is_file() || meta.len() == 0 || meta.len() > MAX_JSON_BYTES {
            return Err(ErrorDetection::ValidationError {
                message: format!("Certificate JSON invalid or too large: {}", cert_path),
                tx_id: None,
            });
        }

        let json_str = fs::read_to_string(&cert_path).map_err(|e| ErrorDetection::IoError {
            message: format!("Failed to read certificate JSON {cert_path}: {e}"),
            code: e.raw_os_error(),
            source: Some(Box::new(e)),
        })?;

        let receipt: CertificateReceipt =
            serde_json::from_str(&json_str).map_err(|e| ErrorDetection::SerializationError {
                details: format!("Failed to parse CertificateReceipt JSON for transfer: {e}"),
            })?;

        receipt.validate()?;

        println!();
        println!("Loaded certificate to transfer:");
        println!("  NFT ID:         {}", receipt.nft_id_hex);
        println!("  Current owner:  {}", receipt.owner_wallet);
        println!(
            "  File:           {} ({} bytes)",
            receipt.file_name, receipt.file_size_bytes
        );
        println!("  Content hash:   {}", receipt.content_hash_hex);
        println!("  Kind / schema:  {} / {}", receipt.kind, receipt.schema);

        if receipt.nft_id_hex.len() != NFT_ID_HEX_LEN {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Invalid nft_id_hex length: expected {} hex chars, got {}",
                    NFT_ID_HEX_LEN,
                    receipt.nft_id_hex.len()
                ),
                tx_id: None,
            });
        }

        let nft_id_bytes = hex::decode(receipt.nft_id_hex.trim()).map_err(|e| {
            ErrorDetection::ValidationError {
                message: format!("Invalid nft_id_hex in certificate (not hex): {e}"),
                tx_id: None,
            }
        })?;

        if nft_id_bytes.len() != NFT_ID_BYTES {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Invalid nft_id_hex length: expected {} bytes, got {}",
                    NFT_ID_BYTES,
                    nft_id_bytes.len()
                ),
                tx_id: None,
            });
        }

        let mut nft_id = [0u8; NFT_ID_BYTES];
        nft_id.copy_from_slice(&nft_id_bytes);

        let tx = NftTransferTx {
            nft_id,
            new_owner_wallet: new_owner.clone(),
        };

        send_net_cmd(NetCmd::SendTxKind(TxKind::NftTransfer(tx)))?;

        println!();
        println!(
            "{}",
            "✅ NFT transfer transaction submitted to mempool / network.".green()
        );
        println!("  NFT ID:            {}", receipt.nft_id_hex);
        println!("  Previous owner:    {}", receipt.owner_wallet);
        println!("  New owner wallet:  {}", new_owner);

        let created_at = Self::runtime_utc_timestamp()?;
        let mut new_description = receipt.description.clone();
        new_description.push_str(&format!(
            " | Transferred to {} at (UTC): {}",
            new_owner, created_at
        ));

        let new_receipt = CertificateReceipt {
            nft_id_hex: receipt.nft_id_hex.clone(),
            owner_wallet: new_owner,
            file_name: receipt.file_name.clone(),
            file_size_bytes: receipt.file_size_bytes,
            content_hash_hex: receipt.content_hash_hex.clone(),
            title: receipt.title.clone(),
            description: new_description,
            created_at_utc: created_at,
            edition: receipt.edition.clone(),
            kind: receipt.kind.clone(),
            schema: receipt.schema,
        };

        if let Err(e) = new_receipt.validate() {
            let msg = format!("Invalid transfer receipt (won't write files): {e:?}");
            json_logger
                .log_error_event("nft", "TransferReceiptInvalid", &msg)
                .ok();
        } else if let Err(e) =
            self.write_certificate_receipt_files(audit_dir, pdf_dir, &new_receipt)
        {
            let msg = format!("Failed to write transfer certificate files: {e:?}");
            json_logger
                .log_error_event("nft", "TransferReceiptWriteFailed", &msg)
                .ok();
        }

        println!();
        println!(
            "{}",
            "📄 New certificate JSON/PDF for the new owner has been written.".green()
        );

        Ok(())
    }
}

impl Default for S10CreateCertificates {
    fn default() -> Self {
        Self::new()
    }
}
