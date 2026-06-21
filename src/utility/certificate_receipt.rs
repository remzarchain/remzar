//! certificate_receipt.rs

use crate::utility::alpha_002_error_detection_system::ErrorDetection;
use crate::utility::helper::{REMZAR_WALLET_LEN, parse_wallet_address};
use serde::{Deserialize, Serialize};

/// Local-only proof / certificate for a minted NFT.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateReceipt {
    pub nft_id_hex: String,
    pub owner_wallet: String,
    pub file_name: String,
    pub file_size_bytes: usize,
    pub content_hash_hex: String,
    pub title: String,
    pub description: String,
    pub created_at_utc: String,
    pub edition: Option<String>,
    pub kind: String,
    pub schema: String,
}

impl CertificateReceipt {
    const MAX_TEXT_BYTES: usize = 2_048;
    const MAX_FILE_NAME_BYTES: usize = 255;
    const MAX_HEX_BYTES: usize = 512;

    /// Remzar NFT ids / content hashes are 64 bytes => 128 hex chars.
    const NFT_ID_HEX_LEN: usize = 128;
    const CONTENT_HASH_HEX_LEN: usize = 128;

    pub fn validate(&self) -> Result<(), ErrorDetection> {
        Self::validate_hex(
            "nft_id_hex",
            self.nft_id_hex.trim(),
            Some(Self::NFT_ID_HEX_LEN),
            Self::MAX_HEX_BYTES,
        )?;

        Self::validate_hex(
            "content_hash_hex",
            self.content_hash_hex.trim(),
            Some(Self::CONTENT_HASH_HEX_LEN),
            Self::MAX_HEX_BYTES,
        )?;

        Self::validate_wallet("owner_wallet", self.owner_wallet.trim())?;
        Self::validate_file_name(self.file_name.trim())?;

        Self::validate_text("title", self.title.trim())?;
        Self::validate_text("description", self.description.trim())?;
        Self::validate_text("created_at_utc", self.created_at_utc.trim())?;
        Self::validate_text("kind", self.kind.trim())?;
        Self::validate_text("schema", self.schema.trim())?;

        if let Some(ed) = &self.edition {
            let ed = ed.trim();
            if !ed.is_empty() {
                Self::validate_text("edition", ed)?;
            }
        }

        Ok(())
    }

    fn validate_text(field: &str, s: &str) -> Result<(), ErrorDetection> {
        if s.is_empty() {
            return Err(ErrorDetection::ValidationError {
                message: format!("{field} cannot be empty"),
                tx_id: None,
            });
        }
        if s.len() > Self::MAX_TEXT_BYTES {
            return Err(ErrorDetection::ValidationError {
                message: format!("{field} too long: max {} bytes", Self::MAX_TEXT_BYTES),
                tx_id: None,
            });
        }
        Ok(())
    }

    fn validate_hex(
        field: &str,
        s: &str,
        expected_len: Option<usize>,
        max_len: usize,
    ) -> Result<(), ErrorDetection> {
        if s.is_empty() {
            return Err(ErrorDetection::ValidationError {
                message: format!("{field} cannot be empty"),
                tx_id: None,
            });
        }
        if s.len() > max_len {
            return Err(ErrorDetection::ValidationError {
                message: format!("{field} too long: max {max_len} chars"),
                tx_id: None,
            });
        }

        if let Some(exact) = expected_len
            && s.len() != exact
        {
            return Err(ErrorDetection::ValidationError {
                message: format!("{field} invalid length: expected {exact}, got {}", s.len()),
                tx_id: None,
            });
        }

        if !s.len().is_multiple_of(2) {
            return Err(ErrorDetection::ValidationError {
                message: format!("{field} hex length must be even"),
                tx_id: None,
            });
        }

        if !s.as_bytes().iter().all(|c| c.is_ascii_hexdigit()) {
            return Err(ErrorDetection::ValidationError {
                message: format!("{field} must be hex"),
                tx_id: None,
            });
        }

        Ok(())
    }

    fn validate_wallet(field: &str, s: &str) -> Result<(), ErrorDetection> {
        if s.len() != REMZAR_WALLET_LEN {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "{field} wallet length must be {}, got {}",
                    REMZAR_WALLET_LEN,
                    s.len()
                ),
                tx_id: None,
            });
        }

        parse_wallet_address(s).map_err(|_| ErrorDetection::ValidationError {
            message: format!("{field} wallet format invalid (expected 'r' + 128 lowercase hex)"),
            tx_id: None,
        })
    }

    fn validate_file_name(name: &str) -> Result<(), ErrorDetection> {
        if name.is_empty() {
            return Err(ErrorDetection::ValidationError {
                message: "file_name cannot be empty".into(),
                tx_id: None,
            });
        }

        if name.len() > Self::MAX_FILE_NAME_BYTES {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "file_name too long: max {} bytes",
                    Self::MAX_FILE_NAME_BYTES
                ),
                tx_id: None,
            });
        }

        if name.contains('/') || name.contains('\\') || name.contains("..") {
            return Err(ErrorDetection::ValidationError {
                message: "file_name contains illegal path characters".into(),
                tx_id: None,
            });
        }

        if name.chars().any(|c| c.is_control()) {
            return Err(ErrorDetection::ValidationError {
                message: "file_name contains control characters".into(),
                tx_id: None,
            });
        }

        Ok(())
    }
}
