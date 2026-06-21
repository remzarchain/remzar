//! utility/audit_report_001_hub.rs

use blake3;
use chrono::{DateTime, Utc};
use hex;
use rust_rocksdb::{DB, IteratorMode, Options};
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};

use crate::blockchain::block_002_blocks::Block;
use crate::blockchain::transaction_004_tx_kind::TxKind;
use crate::blockchain::transaction_005_tx_batch::TransactionBatch;
use crate::utility::helper::get_blockchain_db_dir;
use crate::utility::{
    alpha_001_global_configuration::GlobalConfiguration,
    alpha_002_error_detection_system::ErrorDetection, audit_report_002_pdf as audit_report_pdf,
    audit_report_003_json as audit_report_json,
};

/* ───────────────────────── transaction helper structs ───────────────────────── */

/// A single transaction in the audit report
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct AuditTransaction {
    pub kind: String,
    pub sender: Option<String>,
    pub receiver: Option<String>,
    pub amount: Option<u64>,
}

/* ───────────────────────── data structs ───────────────────────── */

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct AuditBlock {
    pub index: u64,
    pub timestamp: u64,
    pub size: u64,
    pub tx_count: u64,
    pub transactions: Vec<AuditTransaction>,
    pub current_hash: String,
    pub previous_hash: String,
    pub merkle_root: String,
    pub guardian_sig: String,
}

impl From<Block> for AuditBlock {
    fn from(b: Block) -> Self {
        Self {
            index: b.metadata.index,
            timestamp: b.metadata.timestamp,
            size: b.metadata.size,
            tx_count: 0,
            transactions: Vec::new(),
            current_hash: hex::encode(b.block_hash),
            previous_hash: hex::encode(b.metadata.previous_hash),
            merkle_root: hex::encode(b.metadata.merkle_root),
            guardian_sig: hex::encode(b.metadata.guardian_signature),
        }
    }
}

pub struct AuditReport {
    pub blocks: Vec<AuditBlock>,
}

pub type Result<T> = std::result::Result<T, ErrorDetection>;

/* ───────────────────────── impl block ───────────────────────── */

impl AuditReport {
    /// Defensive probe for tx batch storage keys:
    fn best_batch_probe(
        db: &DB,
        tx_cf: &rust_rocksdb::ColumnFamily,
        block: &Block,
    ) -> (usize, usize, Option<Vec<u8>>) {
        let a_key_opt = block.batch_key.as_ref().map(|s| s.as_bytes());
        let b_key = format!("tx_batch_{:010}", block.metadata.index);
        let c_key = block.metadata.index.to_be_bytes();

        fn probe(
            db: &DB,
            tx_cf: &rust_rocksdb::ColumnFamily,
            key: &[u8],
        ) -> Option<(usize, usize, Vec<u8>)> {
            db.get_pinned_cf(tx_cf, key).ok().flatten().map(|pin| {
                let bytes: Vec<u8> = pin.as_ref().to_vec();
                let len = bytes.len();
                let txs = TransactionBatch::deserialize(&bytes)
                    .map(|b| b.transactions.len())
                    .unwrap_or(0);
                (len, txs, bytes)
            })
        }

        let mut best_bytes = 0usize;
        let mut best_txs = 0usize;
        let mut best_blob: Option<Vec<u8>> = None;

        // A
        if let Some(k) = a_key_opt
            && let Some((len, txs, blob)) = probe(db, tx_cf, k)
            && len >= best_bytes
        {
            best_bytes = len;
            best_txs = txs;
            best_blob = Some(blob);
        }

        // B
        if let Some((len, txs, blob)) = probe(db, tx_cf, b_key.as_bytes())
            && len >= best_bytes
        {
            best_bytes = len;
            best_txs = txs;
            best_blob = Some(blob);
        }

        // C
        if let Some((len, txs, blob)) = probe(db, tx_cf, &c_key)
            && len >= best_bytes
        {
            best_bytes = len;
            best_txs = txs;
            best_blob = Some(blob);
        }

        (best_bytes, best_txs, best_blob)
    }

    /* -------- load helpers -------- */
    pub fn load_from_blockchain() -> Result<Self> {
        // 1) Open the blockchain DB with both CFs (using universal path)
        let cf_names = &[
            GlobalConfiguration::BLOCKMINT_DATA_COLUMN_NAME,
            GlobalConfiguration::TRANSACTION_BATCH_COLUMN_NAME,
        ];
        let opts = Options::default();
        let db = DB::open_cf_for_read_only(&opts, get_blockchain_db_dir(), cf_names, false)
            .map_err(|e| ErrorDetection::DatabaseError {
                details: format!(
                    "open blockchain DB (read-only) at {}: {e}",
                    get_blockchain_db_dir().display()
                ),
            })?;

        // 2) Get handles for each CF
        let block_cf = db
            .cf_handle(GlobalConfiguration::BLOCKMINT_DATA_COLUMN_NAME)
            .ok_or_else(|| ErrorDetection::DatabaseError {
                details: format!(
                    "CF '{}' not found",
                    GlobalConfiguration::BLOCKMINT_DATA_COLUMN_NAME
                ),
            })?;
        let tx_cf = db
            .cf_handle(GlobalConfiguration::TRANSACTION_BATCH_COLUMN_NAME)
            .ok_or_else(|| ErrorDetection::DatabaseError {
                details: format!(
                    "CF '{}' not found",
                    GlobalConfiguration::TRANSACTION_BATCH_COLUMN_NAME
                ),
            })?;

        // 3) Iterate blocks, build AuditBlock + transactions
        let mut blocks = Vec::new();
        for (_key, v) in db.iterator_cf(block_cf, IteratorMode::Start).flatten() {
            // a) Try to deserialize the raw Block (WITH SIZES)
            // use stored_block for size math to match Menu 9
            let (blk, _actual_block, stored_block) = match Block::deserialize_with_sizes(&v) {
                Ok(blk) => blk,
                Err(e) => {
                    // Log, skip, but do NOT break!
                    eprintln!("Skipping block: failed to deserialize: {e}");
                    continue;
                }
            };

            // b) Create the AuditBlock skeleton
            let mut audit = AuditBlock::from(blk.clone());

            // c) Look up the corresponding TransactionBatch by index (best probe)
            let (batch_bytes_len, best_txs, best_batch_bytes) =
                Self::best_batch_probe(&db, tx_cf, &blk);

            // d) Align size/tx_count with Menu 9: stored block bytes + batch bytes
            // This matches Menu 9's "Current block size"
            audit.size = (stored_block.saturating_add(batch_bytes_len)) as u64;
            audit.tx_count = best_txs as u64;

            // e) Populate transactions defensively:
            // deserialize from the SAME winning batch bytes used for tx_count
            // (fallback to prior B-key behavior if probe didn't yield bytes)
            if let Some(batch_bytes) = best_batch_bytes {
                match TransactionBatch::deserialize(&batch_bytes) {
                    Ok(batch) => {
                        let mut txs = Vec::with_capacity(batch.transactions.len());
                        for kind in batch.transactions {
                            let tx = match kind {
                                TxKind::Transfer(tx) => AuditTransaction {
                                    kind: "transfer".into(),
                                    sender: Some(String::from_utf8_lossy(&tx.sender).to_string()),
                                    receiver: Some(
                                        String::from_utf8_lossy(&tx.receiver).to_string(),
                                    ),
                                    amount: Some(tx.amount),
                                },
                                TxKind::Reward(rw) => AuditTransaction {
                                    kind: "reward".into(),
                                    sender: None,
                                    receiver: Some(
                                        String::from_utf8_lossy(&rw.receiver)
                                            .trim_end_matches('\0')
                                            .to_string(),
                                    ),
                                    amount: Some(rw.amount),
                                },
                                TxKind::RegisterNode(rn) => AuditTransaction {
                                    kind: "register_node".into(),
                                    sender: None,
                                    receiver: Some(
                                        String::from_utf8_lossy(&rn.wallet_address).to_string(),
                                    ),
                                    amount: None,
                                },
                                TxKind::NftMint(_nft) => AuditTransaction {
                                    kind: "nft_mint".into(),
                                    sender: None,
                                    receiver: None,
                                    amount: None,
                                },
                                TxKind::NftTransfer(nft_tx) => AuditTransaction {
                                    kind: "nft_transfer".into(),
                                    sender: None,
                                    receiver: Some(nft_tx.new_owner_wallet.clone()),
                                    amount: None,
                                },
                            };
                            txs.push(tx);
                        }
                        audit.transactions = txs;
                    }
                    Err(e) => {
                        eprintln!("Skipping transactions for block {}: {e}", audit.index);
                    }
                }
            } else {
                // Fallback: keep existing behavior exactly (B key format)
                let batch_key = format!("tx_batch_{:010}", audit.index);
                if let Ok(Some(batch_bytes)) = db.get_pinned_cf(tx_cf, batch_key.as_bytes()) {
                    match TransactionBatch::deserialize(&batch_bytes) {
                        Ok(batch) => {
                            let mut txs = Vec::with_capacity(batch.transactions.len());
                            for kind in batch.transactions {
                                let tx = match kind {
                                    TxKind::Transfer(tx) => AuditTransaction {
                                        kind: "transfer".into(),
                                        sender: Some(
                                            String::from_utf8_lossy(&tx.sender).to_string(),
                                        ),
                                        receiver: Some(
                                            String::from_utf8_lossy(&tx.receiver).to_string(),
                                        ),
                                        amount: Some(tx.amount),
                                    },
                                    TxKind::Reward(rw) => AuditTransaction {
                                        kind: "reward".into(),
                                        sender: None,
                                        receiver: Some(
                                            String::from_utf8_lossy(&rw.receiver)
                                                .trim_end_matches('\0')
                                                .to_string(),
                                        ),
                                        amount: Some(rw.amount),
                                    },
                                    TxKind::RegisterNode(rn) => AuditTransaction {
                                        kind: "register_node".into(),
                                        sender: None,
                                        receiver: Some(
                                            String::from_utf8_lossy(&rn.wallet_address).to_string(),
                                        ),
                                        amount: None,
                                    },
                                    TxKind::NftMint(_nft) => AuditTransaction {
                                        kind: "nft_mint".into(),
                                        sender: None,
                                        receiver: None,
                                        amount: None,
                                    },
                                    TxKind::NftTransfer(nft_tx) => AuditTransaction {
                                        kind: "nft_transfer".into(),
                                        sender: None,
                                        receiver: Some(nft_tx.new_owner_wallet.clone()),
                                        amount: None,
                                    },
                                };
                                txs.push(tx);
                            }
                            audit.transactions = txs;
                        }
                        Err(e) => {
                            eprintln!("Skipping transactions for block {}: {e}", audit.index);
                        }
                    }
                }
            }

            blocks.push(audit);
        }

        Ok(Self { blocks })
    }

    /// Loads a range of blocks using the given blockchain DB folder path.
    pub fn load_range_with_path<P: AsRef<Path>>(db_path: P, start: u64, end: u64) -> Result<Self> {
        let cf_names = &[
            GlobalConfiguration::BLOCKMINT_DATA_COLUMN_NAME,
            GlobalConfiguration::TRANSACTION_BATCH_COLUMN_NAME,
        ];
        let opts = Options::default();
        let db =
            DB::open_cf_for_read_only(&opts, db_path.as_ref(), cf_names, false).map_err(|e| {
                ErrorDetection::DatabaseError {
                    details: format!("open blockchain DB at {}: {e}", db_path.as_ref().display()),
                }
            })?;

        // 2) Get handles for each CF
        let block_cf = db
            .cf_handle(GlobalConfiguration::BLOCKMINT_DATA_COLUMN_NAME)
            .ok_or_else(|| ErrorDetection::DatabaseError {
                details: format!(
                    "CF '{}' not found (path: {})",
                    GlobalConfiguration::BLOCKMINT_DATA_COLUMN_NAME,
                    db_path.as_ref().display()
                ),
            })?;
        let tx_cf = db
            .cf_handle(GlobalConfiguration::TRANSACTION_BATCH_COLUMN_NAME)
            .ok_or_else(|| ErrorDetection::DatabaseError {
                details: format!(
                    "CF '{}' not found (path: {})",
                    GlobalConfiguration::TRANSACTION_BATCH_COLUMN_NAME,
                    db_path.as_ref().display()
                ),
            })?;

        // 3) Load the requested range
        let mut blocks = Vec::new();
        for idx in start..=end {
            let blk_key = format!("block_{:010}", idx);
            match db.get_pinned_cf(block_cf, blk_key.as_bytes()) {
                Ok(Some(block_bytes)) => {
                    // a) Try to deserialize the block (WITH SIZES)
                    // ✅ IMPORTANT: use stored_block for size math to match Menu 9
                    let (blk, _actual_block, stored_block) =
                        match Block::deserialize_with_sizes(block_bytes.as_ref()) {
                            Ok(blk) => blk,
                            Err(e) => {
                                eprintln!("Skipping block {idx}: failed to deserialize: {e}");
                                continue;
                            }
                        };

                    let mut audit = AuditBlock::from(blk.clone());

                    // b) lookup the matching tx batch (best probe)
                    let (batch_bytes_len, best_txs, best_batch_bytes) =
                        Self::best_batch_probe(&db, tx_cf, &blk);

                    // c) Align size/tx_count with Menu 9: stored block bytes + batch bytes
                    audit.size = (stored_block.saturating_add(batch_bytes_len)) as u64;
                    audit.tx_count = best_txs as u64;

                    // d) Populate transactions defensively (winning batch bytes), fallback to B key
                    if let Some(batch_bytes) = best_batch_bytes {
                        match TransactionBatch::deserialize(&batch_bytes) {
                            Ok(batch) => {
                                let mut txs = Vec::with_capacity(batch.transactions.len());
                                for kind in batch.transactions {
                                    let tx = match kind {
                                        TxKind::Transfer(tx) => AuditTransaction {
                                            kind: "transfer".into(),
                                            sender: Some(
                                                String::from_utf8_lossy(&tx.sender).to_string(),
                                            ),
                                            receiver: Some(
                                                String::from_utf8_lossy(&tx.receiver).to_string(),
                                            ),
                                            amount: Some(tx.amount),
                                        },
                                        TxKind::Reward(rw) => AuditTransaction {
                                            kind: "reward".into(),
                                            sender: None,
                                            receiver: Some(
                                                String::from_utf8_lossy(&rw.receiver)
                                                    .trim_end_matches('\0')
                                                    .to_string(),
                                            ),
                                            amount: Some(rw.amount),
                                        },
                                        TxKind::RegisterNode(rn) => AuditTransaction {
                                            kind: "register_node".into(),
                                            sender: None,
                                            receiver: Some(
                                                String::from_utf8_lossy(&rn.wallet_address)
                                                    .to_string(),
                                            ),
                                            amount: None,
                                        },
                                        TxKind::NftMint(_nft) => AuditTransaction {
                                            kind: "nft_mint".into(),
                                            sender: None,
                                            receiver: None,
                                            amount: None,
                                        },
                                        TxKind::NftTransfer(nft_tx) => AuditTransaction {
                                            kind: "nft_transfer".into(),
                                            sender: None,
                                            receiver: Some(nft_tx.new_owner_wallet.clone()),
                                            amount: None,
                                        },
                                    };
                                    txs.push(tx);
                                }
                                audit.transactions = txs;
                            }
                            Err(e) => {
                                eprintln!("Skipping transactions for block {}: {e}", audit.index);
                            }
                        }
                    } else {
                        // keep existing behavior: B key format
                        let batch_key = format!("tx_batch_{:010}", audit.index);
                        if let Ok(Some(batch_bytes)) = db.get_pinned_cf(tx_cf, batch_key.as_bytes())
                        {
                            match TransactionBatch::deserialize(&batch_bytes) {
                                Ok(batch) => {
                                    let mut txs = Vec::with_capacity(batch.transactions.len());
                                    for kind in batch.transactions {
                                        let tx = match kind {
                                            TxKind::Transfer(tx) => AuditTransaction {
                                                kind: "transfer".into(),
                                                sender: Some(
                                                    String::from_utf8_lossy(&tx.sender).to_string(),
                                                ),
                                                receiver: Some(
                                                    String::from_utf8_lossy(&tx.receiver)
                                                        .to_string(),
                                                ),
                                                amount: Some(tx.amount),
                                            },
                                            TxKind::Reward(rw) => AuditTransaction {
                                                kind: "reward".into(),
                                                sender: None,
                                                receiver: Some(
                                                    String::from_utf8_lossy(&rw.receiver)
                                                        .trim_end_matches('\0')
                                                        .to_string(),
                                                ),
                                                amount: Some(rw.amount),
                                            },
                                            TxKind::RegisterNode(rn) => AuditTransaction {
                                                kind: "register_node".into(),
                                                sender: None,
                                                receiver: Some(
                                                    String::from_utf8_lossy(&rn.wallet_address)
                                                        .to_string(),
                                                ),
                                                amount: None,
                                            },
                                            TxKind::NftMint(_nft) => AuditTransaction {
                                                kind: "nft_mint".into(),
                                                sender: None,
                                                receiver: None,
                                                amount: None,
                                            },
                                            TxKind::NftTransfer(nft_tx) => AuditTransaction {
                                                kind: "nft_transfer".into(),
                                                sender: None,
                                                receiver: Some(nft_tx.new_owner_wallet.clone()),
                                                amount: None,
                                            },
                                        };
                                        txs.push(tx);
                                    }
                                    audit.transactions = txs;
                                }
                                Err(e) => {
                                    eprintln!(
                                        "Skipping transactions for block {}: {e}",
                                        audit.index
                                    );
                                }
                            }
                        }
                    }

                    blocks.push(audit);
                }
                Ok(None) => {
                    // missing block → skip
                }
                Err(e) => {
                    eprintln!("DB error fetching {}: {}", blk_key, e);
                    // skip this one, don't fail all
                    continue;
                }
            }
        }

        Ok(Self { blocks })
    }

    /* -------- canonical serialisation (stable JSON) ---------- */
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        // Compute the real total transactions across all blocks
        let total_tx: u64 = self.blocks.iter().map(|b| b.tx_count).sum();

        // Use the first block’s timestamp as the "snapshot" so the JSON data-hash is stable
        let snapshot_ts: i64 = self
            .blocks
            .first()
            .map(|b| i64::try_from(b.timestamp).unwrap_or(i64::MAX))
            .unwrap_or(0);

        audit_report_json::build_json(self, total_tx, snapshot_ts).map_err(to_io)
    }

    /* -------- JSON export -------- */
    pub fn export_json<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        // Total transactions
        let total_tx: u64 = self.blocks.iter().map(|b| b.tx_count).sum();

        // Real export time for the JSON file
        let export_ts: i64 = Utc::now().timestamp();

        // Build the JSON with both snapshot and export timestamps
        let bytes = audit_report_json::build_json(self, total_tx, export_ts).map_err(to_io)?;

        fs::write(&path, &bytes).map_err(to_io)?;
        Ok(())
    }

    /* -------- PDF export (double-hash) -------- */
    pub fn export_pdf<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        // Use Utc::now() as the snapshot timestamp too
        self.export_pdf_with_time(path, Utc::now())
    }

    pub fn export_pdf_with_time<P: AsRef<Path>>(
        &self,
        path: P,
        snapshot_ts: DateTime<Utc>,
    ) -> Result<()> {
        // 1) Compute data-hash over stable JSON
        let data_bytes = self.canonical_bytes()?;
        let data_hash = blake3::hash(&data_bytes).to_hex().to_string();

        // 2) Compute total_tx
        let total_tx: u64 = self.blocks.iter().map(|b| b.tx_count).sum();

        // 3) Capture actual export-time for the PDF
        let export_ts = Utc::now();

        // 4) First-pass PDF (no hashes yet)
        let first_pdf =
            audit_report_pdf::build_pdf(self, &snapshot_ts, &export_ts, None, total_tx)?;

        // 5) Compute PDF-hash over the first-pass bytes
        let pdf_hash = blake3::hash(&first_pdf).to_hex().to_string();

        // 6) Second-pass PDF (embed both hashes)
        let final_pdf = audit_report_pdf::build_pdf(
            self,
            &snapshot_ts,
            &export_ts,
            Some((&data_hash, &pdf_hash)),
            total_tx,
        )?;

        // 7) Write the PDF
        fs::write(&path, &final_pdf).map_err(to_io)?;
        Ok(())
    }
}

/* ───────────────────────── tiny utils ───────────────────────── */

fn to_io<E: std::fmt::Display>(e: E) -> ErrorDetection {
    ErrorDetection::IoError {
        message: e.to_string(),
        code: None,
        source: None,
    }
}
