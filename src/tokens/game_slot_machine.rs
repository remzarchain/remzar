//! game_001_slot.rs
//! Standalone slot machine mini-game module for REMZAR.
//!
//! Design goals:
//! - Standalone: NO `impl CommandHandler` here.
//! - Production-hardening: input caps, attempt caps, mempool dedupe, balance guards,
//!   and rate limiting to reduce spam/DoS from CLI.
//! - Uses standard Transfer transactions:
//!   1) Player pays 1 ZAR to the HOUSE pool wallet to play.
//!   2) If player wins, HOUSE wallet pays winnings to player.
//!
//! Payout selection is deterministic by guess-closeness.
//
// Payout table (house-favoring):
// - diff = 0        => 100 ZAR
// - diff = 1..=2    => 10 ZAR
// - diff = 3        => 5 ZAR
// - diff = 4..=10   => 2 ZAR
// - diff = 11..=20  => 1 ZAR
// - diff >= 21      => 0 (LOSS)

use colored::Colorize;
use dialoguer::Password;
use once_cell::sync::Lazy;
use rand::RngExt;

use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::sync::Mutex;
use std::time::Duration;
use zeroize::Zeroize;

// --- Project imports (explicit; no super::*; standalone) ---
use crate::blockchain::transaction_001_tx::Transaction;
use crate::blockchain::transaction_004_tx_kind::TxKind;
use crate::cryptography::ml_dsa_65_005_encryption::Cryption;
use crate::network::p2p_010_netcmd::NetCmd;
use crate::runtime::p2p_006_sync_runtime::NodeOpts;
use crate::storage::rocksdb_000_directory::DirectoryDB;
use crate::storage::rocksdb_005_manager::RockDBManager;
use crate::utility::alpha_001_global_configuration::GlobalConfiguration;
use crate::utility::alpha_002_error_detection_system::ErrorDetection;
use crate::utility::hash_system_remzarhash::RemzarHash;
use crate::utility::helper::{
    REMZAR_WALLET_LEN, UNIT_DIVISOR, canon_wallet_id_checked, from_micro_units, to_micro_units_str,
    wallet_id_matches_pubkey_bytes_checked,
};
use crate::utility::logging_data::JsonLogger;

// RocksDB
use rust_rocksdb::{DB, WriteBatch};

/// - Receives entry fees (PLAYER -> HOUSE)
/// - Pays winnings (HOUSE -> PLAYER)
///   NOTE: This wallet is operator-controlled; the player should NEVER be asked for its passphrase.
pub const SLOT_HOUSE_ADDRESS: &str = "rae657f74dd0cda2144c396c54e60c4703866f9c2b486aa0925d2af008de21115e3aa3215409015a1944eeff1474896b261f52564a757bb279e56ecaa123319e7";

/// 1 ZAR entry fee per play (in micro-units).
pub const SLOT_ENTRY_FEE_MICRO: u64 = UNIT_DIVISOR;

/// Local (process) rate-limit: minimum delay between plays per player.
const MIN_COOLDOWN_BETWEEN_SPINS: Duration = Duration::from_millis(900);

/// Caps for user input (DoS / accidental paste).
/// Allow a little extra over REMZAR_WALLET_LEN for pasted whitespace / harmless UI slack.
const MAX_ADDR_INPUT: usize = REMZAR_WALLET_LEN + 8;
const MAX_YN_INPUT: usize = 16;
const MAX_GUESS_INPUT: usize = 16;
const MAX_AMOUNT_INPUT: usize = 64;
const MAX_ATTEMPTS: usize = 3;

/// Defensive cap for wallet blobs loaded from disk.
const MAX_WALLET_FILE_BYTES: u64 = 512 * 1024;

/// Internal in-process map for last play time per player (unix ms).
static LAST_SPIN_AT: Lazy<Mutex<HashMap<String, u64>>> = Lazy::new(|| Mutex::new(HashMap::new()));

/// Result of a single play.
#[derive(Clone, Copy, Debug)]
pub struct SpinResult {
    pub payout_micro: u64,
}

impl SpinResult {
    pub fn is_win(&self) -> bool {
        self.payout_micro > 0
    }
}

/// Configuration for the game (injectable for tests / future tuning).
#[derive(Clone, Debug)]
pub struct SlotMachineGameConfig {
    /// HOUSE pool wallet (receives entry fee and pays winnings)
    pub house_address: &'static str,
    /// Entry fee per play (micro-units)
    pub entry_fee_micro: u64,
}

impl Default for SlotMachineGameConfig {
    fn default() -> Self {
        Self {
            house_address: SLOT_HOUSE_ADDRESS,
            entry_fee_micro: SLOT_ENTRY_FEE_MICRO,
        }
    }
}

/// Minimal context the caller must provide.
pub struct SlotMachineContext<'a> {
    pub opts: &'a NodeOpts,
    pub db: &'a DB,
    pub json_logger: &'a JsonLogger,

    /// fire-and-forget to the network task
    pub send_net_cmd: &'a mut dyn FnMut(NetCmd) -> Result<(), ErrorDetection>,

    /// canonical balance reader (micro-units)
    pub get_balance_micro: &'a mut dyn FnMut(&str) -> u64,
}

/// Main game object.
#[derive(Clone, Debug, Default)]
pub struct SlotMachineGame {
    pub cfg: SlotMachineGameConfig,
}

impl SlotMachineGame {
    /// Max payout in micro-units (guess-game jackpot = 100 ZAR).
    pub fn max_payout_micro(&self) -> u64 {
        100u64.saturating_mul(UNIT_DIVISOR)
    }

    /// Validate static config and return canonical HOUSE wallet.
    fn canonical_house_address(&self) -> Result<String, ErrorDetection> {
        let house = canon_wallet_id_checked(self.cfg.house_address)?;

        if house != self.cfg.house_address {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "HOUSE wallet is not canonical. configured={} canonical={}",
                    self.cfg.house_address, house
                ),
                tx_id: None,
            });
        }

        if self.cfg.entry_fee_micro == 0 {
            return Err(ErrorDetection::ValidationError {
                message: "Slot entry fee must be > 0".into(),
                tx_id: None,
            });
        }

        if self.max_payout_micro() < self.cfg.entry_fee_micro {
            return Err(ErrorDetection::ValidationError {
                message: "Slot max payout must be >= entry fee".into(),
                tx_id: None,
            });
        }

        Ok(house)
    }

    /// New: generate target in [1..=100].
    fn gen_target_1_100(&self) -> u32 {
        let mut rng = rand::rng();
        let mut b = [0u8; 4];
        rng.fill(&mut b);

        let n = u32::from_be_bytes(b);

        let rem = n.checked_rem(100).unwrap_or(0);
        rem.checked_add(1).unwrap_or(1)
    }

    /// Payout based on closeness, updated to be more house-favoring:
    /// - diff = 0        => 100 ZAR
    /// - diff = 1..=2    => 10 ZAR
    /// - diff = 3        => 5 ZAR
    /// - diff = 4..=10   => 2 ZAR
    /// - diff = 11..=20  => 1 ZAR
    /// - diff >= 21      => 0
    fn payout_from_guess(&self, target: u32, guess: u32) -> u64 {
        if target == 0 {
            return 0;
        }

        let diff = u64::from(target.abs_diff(guess));

        let payout_remzar: u64 = if diff == 0 {
            100
        } else if diff <= 2 {
            10
        } else if diff == 3 {
            5
        } else if diff <= 10 {
            2
        } else if diff <= 20 {
            1
        } else {
            0
        };

        payout_remzar.saturating_mul(UNIT_DIVISOR)
    }

    /// CLI: play once with interactive prompts and hardened input limits.
    pub fn play_once_interactive(
        &self,
        ctx: &mut SlotMachineContext<'_>,
    ) -> Result<(), ErrorDetection> {
        let house_wallet = self.canonical_house_address()?;

        println!();
        println!("{}", "🎰 Remzar Slot Machine".magenta().bold());
        println!(
            "{}",
            format!(
                "Cost: {:.8} ZAR per play. Entry fee goes to HOUSE pool: {}",
                from_micro_units(self.cfg.entry_fee_micro),
                house_wallet
            )
            .cyan()
        );
        println!(
            "{}",
            format!("HOUSE pool / payout wallet: {}", house_wallet).cyan()
        );

        if !read_yes_no_capped("Do you want to play? (yes/no): ", MAX_YN_INPUT)? {
            println!("{}", "❌ Returning to menu.".red());
            return Ok(());
        }

        // Player address
        let player = read_wallet_capped("Enter PLAYER wallet address: ", MAX_ADDR_INPUT)?;

        if player == house_wallet {
            return Err(ErrorDetection::ValidationError {
                message: "PLAYER wallet must not be the HOUSE wallet.".into(),
                tx_id: None,
            });
        }

        // Amount to pay: fixed at 1.00 ZAR per play.
        let fee_micro = loop {
            println!(
                "{}",
                format!(
                    "Entry fee is fixed at {:.8} ZAR per play.",
                    from_micro_units(self.cfg.entry_fee_micro)
                )
                .yellow()
            );

            let s = read_line_capped(
                "Enter entry fee to send (press Enter for default): ",
                MAX_AMOUNT_INPUT,
            )?;

            if s.trim().is_empty() {
                break self.cfg.entry_fee_micro;
            }

            let amt = to_micro_units_str(&s);
            if amt == 0 {
                println!(
                    "{}",
                    "❌ Invalid amount. Must be 1.00000000 ZAR (8 decimals max).".red()
                );
                continue;
            }
            if amt != self.cfg.entry_fee_micro {
                println!(
                    "{}",
                    format!(
                        "❌ Entry fee must be exactly {:.8} ZAR.",
                        from_micro_units(self.cfg.entry_fee_micro)
                    )
                    .red()
                );
                continue;
            }
            break amt;
        };

        // Process-local cooldown to reduce spam.
        self.enforce_cooldown(&player)?;

        // Ownership proof: PLAYER only (player is spending).
        self.prove_wallet_ownership(ctx.opts, &player, "PLAYER", ctx.json_logger)?;

        // Balance guards (canonical via callback)
        let player_bal = (ctx.get_balance_micro)(&player);
        if player_bal < fee_micro {
            println!(
                "{}",
                format!(
                    "❌ PLAYER insufficient funds: need {:.8}, have {:.8}",
                    from_micro_units(fee_micro),
                    from_micro_units(player_bal),
                )
                .red()
            );
            return Ok(());
        }

        // House solvency guard: must cover max payout right now.
        let house_bal = (ctx.get_balance_micro)(&house_wallet);
        let max_payout = self.max_payout_micro();
        if house_bal < max_payout {
            println!(
                "{}",
                format!(
                    "❌ HOUSE underfunded: needs >= {:.8} ZAR to cover max payout; has {:.8}",
                    from_micro_units(max_payout),
                    from_micro_units(house_bal),
                )
                .red()
            );
            return Ok(());
        }

        println!();
        println!("{}", "Summary".bold().cyan());
        println!(
            "PLAYER: {}  bal {:.8}",
            player.green(),
            from_micro_units(player_bal)
        );
        println!(
            "HOUSE : {}  bal {:.8}",
            house_wallet.green(),
            from_micro_units(house_bal)
        );
        println!(
            "FEE   : {:.8} -> HOUSE ({})",
            from_micro_units(fee_micro),
            house_wallet.dimmed()
        );
        println!(
            "MAX PAYOUT COVERED: {:.8} ZAR",
            from_micro_units(max_payout)
        );

        if !read_yes_no_capped(
            &format!(
                "Send {:.8} ZAR entry fee to HOUSE and play? (yes/no): ",
                from_micro_units(fee_micro)
            ),
            MAX_YN_INPUT,
        )? {
            println!("{}", "❌ Cancelled.".red());
            return Ok(());
        }

        // Re-check funds (TOCTOU paranoia)
        let player_now = (ctx.get_balance_micro)(&player);
        if player_now < fee_micro {
            println!(
                "{}",
                format!(
                    "❌ PLAYER balance changed; need {:.8} have {:.8}",
                    from_micro_units(fee_micro),
                    from_micro_units(player_now),
                )
                .red()
            );
            return Ok(());
        }

        let house_now = (ctx.get_balance_micro)(&house_wallet);
        if house_now < max_payout {
            println!(
                "{}",
                format!(
                    "❌ HOUSE balance changed; need {:.8} have {:.8}",
                    from_micro_units(max_payout),
                    from_micro_units(house_now),
                )
                .red()
            );
            return Ok(());
        }

        // 1) Entry fee tx: PLAYER -> HOUSE
        enqueue_transfer_to_mempool(ctx.db, &player, &house_wallet, fee_micro, ctx.json_logger)?;
        (ctx.send_net_cmd)(NetCmd::SendTx(Transaction::new(
            player.clone(),
            house_wallet.clone(),
            fee_micro,
        )?))?;

        println!(
            "{}",
            format!(
                "💰 Entry fee queued: {:.8} ZAR  {} -> {}",
                from_micro_units(fee_micro),
                player.green(),
                house_wallet.green()
            )
            .yellow()
        );

        // 2) Guess game
        println!();
        println!("{}", "🎯 Guess Game (1–100)".magenta().bold());

        let target = self.gen_target_1_100();
        let guess = read_guess_1_100("Enter your guess (1-100): ", MAX_GUESS_INPUT)?;

        let payout_micro = self.payout_from_guess(target, guess);

        // Report
        let diff = u64::from(target.abs_diff(guess));
        let pct_bps = diff.saturating_mul(100);

        let pct_int = pct_bps.div_euclid(100);
        let pct_frac = pct_bps.rem_euclid(100);
        println!(
            "{}",
            format!(
                "Target: {}  |  Your guess: {}  |  Off by: {}  |  Off: {}.{:02}%",
                target, guess, diff, pct_int, pct_frac
            )
            .cyan()
        );

        // 3) Payout tx (HOUSE -> PLAYER)
        if payout_micro > 0 {
            let house_pay_now = (ctx.get_balance_micro)(&house_wallet);
            if house_pay_now < payout_micro {
                println!(
                    "{}",
                    format!(
                        "❌ HOUSE balance insufficient for this payout now (need {:.8}, have {:.8}).",
                        from_micro_units(payout_micro),
                        from_micro_units(house_pay_now)
                    )
                    .red()
                );
                return Ok(());
            }

            enqueue_transfer_to_mempool(
                ctx.db,
                &house_wallet,
                &player,
                payout_micro,
                ctx.json_logger,
            )?;
            (ctx.send_net_cmd)(NetCmd::SendTx(Transaction::new(
                house_wallet.clone(),
                player.clone(),
                payout_micro,
            )?))?;

            println!();
            println!("{}", "🎉 WIN!".green().bold());
            println!(
                "{}",
                format!("Prize: {:.8} ZAR", from_micro_units(payout_micro)).green()
            );
            println!(
                "{}",
                format!(
                    "💸 Payout queued: {:.8} ZAR  {} -> {}",
                    from_micro_units(payout_micro),
                    house_wallet.green(),
                    player.green()
                )
                .green()
            );
        } else {
            println!();
            println!("{}", "😿 LOSS".red().bold());
            println!("{}", "No prize this round.".red());
        }

        Ok(())
    }

    /// Wallet ownership proof by decrypting the wallet file with passphrase + confirm.
    pub fn prove_wallet_ownership(
        &self,
        opts: &NodeOpts,
        wallet_addr: &str,
        label: &str,
        json_logger: &JsonLogger,
    ) -> Result<(), ErrorDetection> {
        let wallet_addr = canon_wallet_id_checked(wallet_addr)?;

        let directory = DirectoryDB::from_node_opts(opts).map_err(|e| {
            let msg = format!("Slot: failed to initialise directories: {e}");
            json_logger
                .log_error_event("slot", "InitDirectoriesFailed", &msg)
                .ok();
            ErrorDetection::StorageError { message: msg }
        })?;

        let wallet_file = directory.wallets_path.join(format!("{wallet_addr}.wallet"));

        let meta = fs::metadata(&wallet_file).map_err(|e| {
            let msg = format!(
                "{label} wallet file not found at {}: {e}",
                wallet_file.display()
            );
            json_logger
                .log_error_event("slot", "WalletFileMissing", &msg)
                .ok();
            ErrorDetection::NotFound { resource: msg }
        })?;

        if !meta.is_file() {
            let msg = format!(
                "{label} wallet path is not a file: {}",
                wallet_file.display()
            );
            json_logger
                .log_error_event("slot", "WalletPathInvalid", &msg)
                .ok();
            return Err(ErrorDetection::ValidationError {
                message: msg,
                tx_id: None,
            });
        }

        if meta.len() == 0 {
            let msg = format!("{label} wallet file is empty: {}", wallet_file.display());
            json_logger
                .log_error_event("slot", "WalletFileEmpty", &msg)
                .ok();
            return Err(ErrorDetection::ValidationError {
                message: msg,
                tx_id: None,
            });
        }

        if meta.len() > MAX_WALLET_FILE_BYTES {
            let msg = format!(
                "{label} wallet file too large: {} bytes (max {})",
                meta.len(),
                MAX_WALLET_FILE_BYTES
            );
            json_logger
                .log_error_event("slot", "WalletFileTooLarge", &msg)
                .ok();
            return Err(ErrorDetection::ValidationError {
                message: msg,
                tx_id: None,
            });
        }

        for attempt in 1..=MAX_ATTEMPTS {
            let mut pass = Password::new()
                .with_prompt(format!("🔒 Enter passphrase for {label} wallet"))
                .allow_empty_password(false)
                .interact()
                .map_err(|e| ErrorDetection::IoError {
                    message: format!("Failed to read passphrase: {e}"),
                    code: None,
                    source: Some(Box::new(e)),
                })?;

            let mut confirm = Password::new()
                .with_prompt(format!("🔒 Confirm passphrase for {label} wallet"))
                .allow_empty_password(false)
                .interact()
                .map_err(|e| ErrorDetection::IoError {
                    message: format!("Failed to read passphrase confirmation: {e}"),
                    code: None,
                    source: Some(Box::new(e)),
                })?;

            if pass != confirm {
                pass.zeroize();
                confirm.zeroize();

                json_logger
                    .log_error_event(
                        "slot",
                        "WalletPassphraseMismatch",
                        &format!("{label} passphrase mismatch (attempt {attempt}/{MAX_ATTEMPTS})"),
                    )
                    .ok();

                println!("{}", "❌ Passphrase confirmation does not match.".red());
                if attempt == MAX_ATTEMPTS {
                    return Err(ErrorDetection::ValidationError {
                        message: format!("{label} passphrase confirmation failed."),
                        tx_id: None,
                    });
                }
                continue;
            }

            confirm.zeroize();

            let mut encrypted = match fs::read(&wallet_file) {
                Ok(v) => v,
                Err(e) => {
                    pass.zeroize();
                    let msg = format!("Failed to read wallet file: {e}");
                    json_logger
                        .log_error_event("slot", "ReadWalletFileFailed", &msg)
                        .ok();
                    return Err(ErrorDetection::IoError {
                        message: msg,
                        code: e.raw_os_error(),
                        source: Some(Box::new(e)),
                    });
                }
            };

            // ✅ bytes decrypt + shared key↔wallet proof
            let verified = (|| -> Result<(), ErrorDetection> {
                use fips204::ml_dsa_65;
                use fips204::traits::{SerDes, Signer};
                use zeroize::Zeroize;

                // 1) Decrypt to bytes (no UTF-8 assumptions)
                let mut sk_bytes = Cryption::decrypt_private_key_bytes(&encrypted, &pass)?;

                // 2) Accept raw (4032 bytes) OR legacy hex (8064 chars) and decode it
                let mut raw: Vec<u8> = match sk_bytes.len() {
                    n if n == ml_dsa_65::SK_LEN => sk_bytes,
                    n if n == Cryption::ML_DSA_65_SECRET_HEX_CHARS => {
                        let mut decoded = match hex::decode(&sk_bytes) {
                            Ok(v) => v,
                            Err(e) => {
                                sk_bytes.zeroize();
                                return Err(ErrorDetection::ValidationError {
                                    message: format!("Hex decode failed: {e}"),
                                    tx_id: None,
                                });
                            }
                        };

                        sk_bytes.zeroize();

                        if decoded.len() != ml_dsa_65::SK_LEN {
                            let got = decoded.len();
                            decoded.zeroize();
                            return Err(ErrorDetection::ValidationError {
                                message: format!(
                                    "Decoded secret length mismatch: expected {} bytes, got {}",
                                    ml_dsa_65::SK_LEN,
                                    got
                                ),
                                tx_id: None,
                            });
                        }
                        decoded
                    }
                    got => {
                        sk_bytes.zeroize();
                        return Err(ErrorDetection::ValidationError {
                            message: format!(
                                "Unsupported wallet payload length: got {} (expected {} raw or {} hex)",
                                got,
                                ml_dsa_65::SK_LEN,
                                Cryption::ML_DSA_65_SECRET_HEX_CHARS
                            ),
                            tx_id: None,
                        });
                    }
                };

                // 3) Vec -> fixed array
                let sk_arr: [u8; ml_dsa_65::SK_LEN] = match raw.as_slice().try_into() {
                    Ok(a) => a,
                    Err(_) => {
                        raw.zeroize();
                        return Err(ErrorDetection::ValidationError {
                            message: format!(
                                "Failed to convert secret to [u8; {}]",
                                ml_dsa_65::SK_LEN
                            ),
                            tx_id: None,
                        });
                    }
                };

                // wipe plaintext ASAP
                raw.zeroize();

                // 4) Reconstruct key and prove pubkey ↔ wallet binding using shared helper
                let sk = match ml_dsa_65::PrivateKey::try_from_bytes(sk_arr) {
                    Ok(k) => k,
                    Err(e) => {
                        return Err(ErrorDetection::CryptographicError {
                            message: format!("Invalid ML-DSA-65 secret key bytes: {e}"),
                        });
                    }
                };

                let pk = sk.get_public_key();
                let pk_bytes = pk.into_bytes();

                wallet_id_matches_pubkey_bytes_checked(&wallet_addr, &pk_bytes)?;

                Ok(())
            })();

            // Wipe secrets regardless
            pass.zeroize();
            encrypted.zeroize();

            match verified {
                Ok(()) => return Ok(()),
                Err(_) => {
                    json_logger
                        .log_error_event(
                            "slot",
                            "WalletDecryptFailed",
                            &format!("{label} decrypt failed (attempt {attempt}/{MAX_ATTEMPTS})"),
                        )
                        .ok();

                    println!("{}", "❌ Wrong passphrase. Try again.".red());
                    if attempt == MAX_ATTEMPTS {
                        return Err(ErrorDetection::DecryptionError {
                            message: format!("{label} wallet decryption failed."),
                        });
                    }
                }
            }
        }

        Err(ErrorDetection::DecryptionError {
            message: format!("{label} wallet decryption failed."),
        })
    }

    /// Process-local cooldown to reduce CLI spam.
    fn enforce_cooldown(&self, player: &str) -> Result<(), ErrorDetection> {
        let now = unix_millis()?;

        let mut map = LAST_SPIN_AT
            .lock()
            .map_err(|_| ErrorDetection::ExecutionError {
                details: "Slot rate-limit mutex poisoned".into(),
            })?;

        if let Some(prev) = map.get(player).copied() {
            let delta_ms = now.saturating_sub(prev);
            let cooldown_ms =
                u64::try_from(MIN_COOLDOWN_BETWEEN_SPINS.as_millis()).unwrap_or(u64::MAX);

            if delta_ms < cooldown_ms {
                let remaining_ms = cooldown_ms.saturating_sub(delta_ms);
                return Err(ErrorDetection::ValidationError {
                    message: format!("Slow down: wait ~{}ms between plays.", remaining_ms),
                    tx_id: None,
                });
            }
        }

        map.insert(player.to_string(), now);
        Ok(())
    }
}

/// Enqueue a Transfer into mempool:
/// - Serialize TxKind::Transfer(tx)
/// - Hash bytes with RemzarHash
/// - Dedupe using TX_TO_HASH CF
/// - Write both CFs using WriteBatch
pub fn enqueue_transfer_to_mempool(
    db: &DB,
    sender: &str,
    receiver: &str,
    amount_micro: u64,
    json_logger: &JsonLogger,
) -> Result<(), ErrorDetection> {
    let sender = canon_wallet_id_checked(sender)?;
    let receiver = canon_wallet_id_checked(receiver)?;

    if sender == receiver {
        return Err(ErrorDetection::ValidationError {
            message: "Refusing self-transfer.".into(),
            tx_id: None,
        });
    }

    if amount_micro == 0 {
        return Err(ErrorDetection::ValidationError {
            message: "Amount must be > 0.".into(),
            tx_id: None,
        });
    }

    let tx = Transaction::new(sender, receiver, amount_micro)?;
    let kind = TxKind::Transfer(tx);

    let tx_bytes =
        postcard::to_allocvec(&kind).map_err(|e| ErrorDetection::SerializationError {
            details: format!("TxKind serialize failed: {e}"),
        })?;
    let hash = RemzarHash::compute_bytes_hash(&tx_bytes);

    let cf_tx = db
        .cf_handle(GlobalConfiguration::TRANSACTION_COLUMN_NAME)
        .ok_or_else(|| ErrorDetection::DatabaseError {
            details: format!(
                "{} CF missing",
                GlobalConfiguration::TRANSACTION_COLUMN_NAME
            ),
        })?;
    let cf_hash = db
        .cf_handle(GlobalConfiguration::TX_TO_HASH_COLUMN_NAME)
        .ok_or_else(|| ErrorDetection::DatabaseError {
            details: format!("{} CF missing", GlobalConfiguration::TX_TO_HASH_COLUMN_NAME),
        })?;

    if db
        .get_pinned_cf(cf_hash, hash.as_slice())
        .map_err(|e| ErrorDetection::StorageError {
            message: format!("Failed to check existing tx hash: {e}"),
        })?
        .is_none()
    {
        let ts_key = make_ts_key()?;

        let mut wb = WriteBatch::default();
        wb.put_cf(cf_tx, ts_key.as_bytes(), &tx_bytes);
        wb.put_cf(cf_hash, hash.as_slice(), &tx_bytes);

        db.write_opt(&wb, &RockDBManager::sync_write_options())
            .map_err(|e| {
                let msg = format!("Failed adding tx to mempool: {e}");
                json_logger
                    .log_error_event("slot", "WriteMempoolFailed", &msg)
                    .ok();
                ErrorDetection::StorageError { message: msg }
            })?;
    } else {
        json_logger
            .log_error_event("slot", "MempoolDedupeHit", "tx hash already present")
            .ok();
    }

    Ok(())
}

// --- hardened I/O helpers ---

fn read_line_capped(prompt: &str, cap: usize) -> Result<String, ErrorDetection> {
    print!("{prompt}");
    io::stdout().flush().map_err(|e| ErrorDetection::IoError {
        message: format!("Failed to flush stdout: {e}"),
        code: e.raw_os_error(),
        source: Some(Box::new(e)),
    })?;

    let mut s = String::new();
    io::stdin()
        .read_line(&mut s)
        .map_err(|e| ErrorDetection::IoError {
            message: format!("Failed to read input: {e}"),
            code: e.raw_os_error(),
            source: Some(Box::new(e)),
        })?;

    let trimmed = s.trim().to_string();

    if trimmed.len() > cap {
        return Err(ErrorDetection::ValidationError {
            message: format!("Input too long (max {cap} chars)"),
            tx_id: None,
        });
    }

    if trimmed.chars().any(|c| c == '\0' || c.is_control()) {
        return Err(ErrorDetection::ValidationError {
            message: "Input contains invalid control characters".into(),
            tx_id: None,
        });
    }

    Ok(trimmed)
}

fn read_wallet_capped(prompt: &str, cap: usize) -> Result<String, ErrorDetection> {
    let raw = read_line_capped(prompt, cap)?;
    canon_wallet_id_checked(&raw)
}

fn read_yes_no_capped(prompt: &str, cap: usize) -> Result<bool, ErrorDetection> {
    for _ in 0..MAX_ATTEMPTS {
        let s = read_line_capped(prompt, cap)?;
        let v = s.trim().to_ascii_lowercase();

        match v.as_str() {
            "yes" | "y" => return Ok(true),
            "no" | "n" => return Ok(false),
            _ => {
                println!("{}", "❌ Please type yes or no.".red());
            }
        }
    }

    Err(ErrorDetection::ValidationError {
        message: "Too many invalid yes/no responses.".into(),
        tx_id: None,
    })
}

fn read_guess_1_100(prompt: &str, cap: usize) -> Result<u32, ErrorDetection> {
    for _ in 0..MAX_ATTEMPTS {
        let s = read_line_capped(prompt, cap)?;
        let Ok(n) = s.trim().parse::<u32>() else {
            println!("{}", "❌ Please enter digits only (1-100).".red());
            continue;
        };
        if (1..=100).contains(&n) {
            return Ok(n);
        }
        println!("{}", "❌ Guess must be between 1 and 100.".red());
    }
    Err(ErrorDetection::ValidationError {
        message: "Too many invalid guesses.".into(),
        tx_id: None,
    })
}

fn unix_secs() -> Result<u64, ErrorDetection> {
    u64::try_from(chrono::Utc::now().timestamp()).map_err(|_| ErrorDetection::TimestampError {
        message: "System time before UNIX_EPOCH.".into(),
        details: "chrono::Utc::now().timestamp() returned a negative value".into(),
        source: None,
    })
}

fn unix_millis() -> Result<u64, ErrorDetection> {
    u64::try_from(chrono::Utc::now().timestamp_millis()).map_err(|_| {
        ErrorDetection::TimestampError {
            message: "System time before UNIX_EPOCH.".into(),
            details: "chrono::Utc::now().timestamp_millis() returned a negative value".into(),
            source: None,
        }
    })
}

fn make_ts_key() -> Result<String, ErrorDetection> {
    let now = unix_secs()?;

    let mut rng = rand::rng();
    let mut rnd = [0u8; 4];
    rng.fill(&mut rnd);

    let r = u32::from_be_bytes(rnd);
    Ok(format!("tx_{}_{}", now, r))
}

/*
Updated payout table:

Win 100 ZAR (jackpot)
Condition: diff = 0 (exact match)

Win 10 ZAR
Condition: diff = 1..=2

Win 5 ZAR
Condition: diff = 3

Win 2 ZAR
Condition: diff = 4..=10

Win 1 ZAR
Condition: diff = 11..=20

LOSS
Condition: diff >= 21
*/
