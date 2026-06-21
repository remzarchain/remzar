// src/blockchain/transaction_004_tx_kind.rs

use crate::blockchain::transaction_001_tx::Transaction;
use crate::blockchain::transaction_002_tx_register::RegisterNodeTx;
use crate::blockchain::transaction_003_tx_reward::RewardTx;
use crate::tokens::nft_001::{NftMintTx, NftTransferTx};
use crate::utility::alpha_002_error_detection_system::ErrorDetection;
use crate::utility::helper::{canon_wallet_id_checked, parse_wallet_address_bytes};

use postcard::take_from_bytes;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum TxKind {
    Transfer(Transaction),
    RegisterNode(RegisterNodeTx),
    Reward(RewardTx),
    NftMint(NftMintTx),
    NftTransfer(NftTransferTx),
}

impl TxKind {
    /// Serializes the `TxKind` enum into a vector of bytes, using robust error handling.
    pub fn serialize(&self) -> Result<Vec<u8>, ErrorDetection> {
        postcard::to_allocvec(self).map_err(|e| ErrorDetection::SerializationError {
            details: format!("Failed to serialize TxKind variant: {}", e),
        })
    }

    /// Deserializes bytes into a `TxKind` enum and validates the decoded variant.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, ErrorDetection> {
        let (tx_kind, remaining): (Self, &[u8]) =
            take_from_bytes(bytes).map_err(|e| ErrorDetection::SerializationError {
                details: format!("Failed to deserialize TxKind: {}", e),
            })?;

        if !remaining.is_empty() {
            return Err(ErrorDetection::SerializationError {
                details: format!(
                    "Failed to deserialize TxKind: trailing bytes after payload: {} bytes",
                    remaining.len()
                ),
            });
        }

        tx_kind.validate()?;
        Ok(tx_kind)
    }

    /// Validate the contents of the `TxKind` enum, ensuring no invalid data.
    pub fn validate(&self) -> Result<(), ErrorDetection> {
        match self {
            TxKind::Transfer(tx) => tx.validate().map_err(|e| ErrorDetection::ValidationError {
                message: format!("Invalid Transfer transaction: {}", e),
                tx_id: None,
            }),

            TxKind::RegisterNode(tx) => {
                tx.validate().map_err(|e| ErrorDetection::ValidationError {
                    message: format!("Invalid RegisterNode transaction: {}", e),
                    tx_id: None,
                })
            }

            TxKind::Reward(tx) => tx.validate().map_err(|e| ErrorDetection::ValidationError {
                message: format!("Invalid Reward transaction: {}", e),
                tx_id: None,
            }),

            // NftMint does not mutate balances; structural validation is handled at parsing/construction time.
            TxKind::NftMint(_tx) => Ok(()),

            // NftTransfer: minimal structural validation here.
            TxKind::NftTransfer(tx) => {
                if tx.new_owner_wallet.trim().is_empty() {
                    return Err(ErrorDetection::ValidationError {
                        message: "Invalid NftTransfer: new_owner_wallet is empty".into(),
                        tx_id: None,
                    });
                }

                // Align with Remzar wallet format:
                // canonical wallet id: 'r' + 128 lowercase hex (129 chars total)
                canon_wallet_id_checked(&tx.new_owner_wallet).map_err(|e| {
                    ErrorDetection::ValidationError {
                        message: format!("Invalid NftTransfer: {}", e),
                        tx_id: None,
                    }
                })?;

                Ok(())
            }
        }
    }

    // ─────────────────────────────────────────────────────────────
    // Helpers for account-model flushing & address handling
    // ─────────────────────────────────────────────────────────────

    /// Return the normalized sender address if this tx has one.
    pub fn normalized_sender(&self) -> Option<String> {
        match self {
            TxKind::Transfer(tx) => {
                let s = normalize_address_bytes(&tx.sender);
                if s.is_empty() { None } else { Some(s) }
            }
            _ => None,
        }
    }

    /// Return the normalized receiver address if this tx has one.
    /// Transfer + Reward.
    pub fn normalized_receiver(&self) -> Option<String> {
        match self {
            TxKind::Transfer(tx) => {
                let r = normalize_address_bytes(&tx.receiver);
                if r.is_empty() { None } else { Some(r) }
            }
            TxKind::Reward(tx) => {
                let r = normalize_address_bytes(&tx.receiver);
                if r.is_empty() { None } else { Some(r) }
            }
            _ => None,
        }
    }

    /// Return all normalized addresses whose balances this tx mutates.
    pub fn touched_addresses(&self) -> Vec<String> {
        let mut set: HashSet<String> = HashSet::new();

        match self {
            TxKind::Transfer(tx) => {
                let s = normalize_address_bytes(&tx.sender);
                if !s.is_empty() {
                    set.insert(s);
                }

                let r = normalize_address_bytes(&tx.receiver);
                if !r.is_empty() {
                    set.insert(r);
                }
            }

            TxKind::Reward(tx) => {
                let r = normalize_address_bytes(&tx.receiver);
                if !r.is_empty() {
                    set.insert(r);
                }
            }

            TxKind::RegisterNode(_) | TxKind::NftMint(_) | TxKind::NftTransfer(_) => {
                // No account balance mutation here.
            }
        }

        set.into_iter().collect()
    }

    /// Small human-friendly tag for logs.
    pub fn tag(&self) -> &'static str {
        match self {
            TxKind::Transfer(_) => "transfer",
            TxKind::Reward(_) => "reward",
            TxKind::RegisterNode(_) => "register_node",
            TxKind::NftMint(_) => "nft_mint",
            TxKind::NftTransfer(_) => "nft_transfer",
        }
    }
}

/// Normalize a wallet address possibly stored as padded bytes:
#[inline]
pub fn normalize_address_bytes(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .rposition(|byte| *byte != 0)
        .map_or(0, |last_non_zero_index| {
            last_non_zero_index.saturating_add(1)
        });

    let Some(trimmed) = bytes.get(..end) else {
        return String::new();
    };

    if trimmed.is_empty() {
        return String::new();
    }

    if trimmed.contains(&0) {
        return String::new();
    }

    match parse_wallet_address_bytes(trimmed) {
        Ok(s) => s.to_string(),
        Err(_) => String::new(),
    }
}
