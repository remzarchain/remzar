//! Genesis File for Remzar blockchain

use crate::blockchain::genesis_001_block::GenesisBlock;
use crate::utility::alpha_001_global_configuration::GlobalConfiguration;
use crate::utility::alpha_002_error_detection_system::ErrorDetection;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Main struct representing all genesis config for the chain.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GenesisFile {
    pub chain_id: String,
    pub description: Option<String>,
    pub version: Option<String>,
    pub genesis_block: GenesisBlock,
}

impl GenesisFile {
    /// Load a GenesisFile from a JSON file path.
    pub fn from_json_file(path: &str) -> Result<Self, ErrorDetection> {
        // Defensive: bound file size before reading entire thing into memory
        let p = Path::new(path);

        let meta = fs::metadata(p).map_err(|e| ErrorDetection::SerializationError {
            details: e.to_string(),
        })?;

        let cap = GlobalConfiguration::MAX_GENESIS_JSON_BYTES;

        // If metadata is enormous or cannot fit into usize safely, refuse.
        if meta.len() > cap {
            return Err(ErrorDetection::SerializationError {
                details: format!(
                    "Genesis JSON file too large: {} bytes (cap {})",
                    meta.len(),
                    cap
                ),
            });
        }

        let data = fs::read_to_string(p).map_err(|e| ErrorDetection::SerializationError {
            details: e.to_string(),
        })?;

        let g: Self =
            serde_json::from_str(&data).map_err(|e| ErrorDetection::SerializationError {
                details: e.to_string(),
            })?;

        // Always validate after load so callers don't forget.
        g.validate()?;
        Ok(g)
    }

    /// Save a GenesisFile to a JSON file path.
    pub fn to_json_file(&self, path: &str) -> Result<(), ErrorDetection> {
        let json =
            serde_json::to_string_pretty(self).map_err(|e| ErrorDetection::SerializationError {
                details: e.to_string(),
            })?;

        let cap = usize::try_from(GlobalConfiguration::MAX_GENESIS_JSON_BYTES).map_err(|_| {
            ErrorDetection::ValidationError {
                message: format!(
                    "Invalid MAX_GENESIS_JSON_BYTES (cannot fit into usize on this platform): {}",
                    GlobalConfiguration::MAX_GENESIS_JSON_BYTES
                ),
                tx_id: None,
            }
        })?;

        if json.len() > cap {
            return Err(ErrorDetection::SerializationError {
                details: format!(
                    "Refusing to write genesis JSON: {} bytes (cap {})",
                    json.len(),
                    GlobalConfiguration::MAX_GENESIS_JSON_BYTES
                ),
            });
        }

        fs::write(path, json).map_err(|e| ErrorDetection::SerializationError {
            details: e.to_string(),
        })
    }

    /// Validate both the block and version for correctness.
    pub fn validate(&self) -> Result<(), ErrorDetection> {
        // 1. Check chain_id is present and non-empty
        if self.chain_id.trim().is_empty() {
            return Err(ErrorDetection::ValidationError {
                message: "GenesisFile chain_id is empty".into(),
                tx_id: None,
            });
        }

        if self.chain_id.len() > 128 {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "GenesisFile chain_id too long ({} bytes; max 128)",
                    self.chain_id.len()
                ),
                tx_id: None,
            });
        }

        // 2. Check version is present and matches semantic version pattern
        if let Some(ver) = &self.version {
            // Simple regex for semantic version like "1.0.0" or "2.1.3-beta"
            let semver_pattern = match regex::Regex::new(r"^\d+\.\d+\.\d+(-[a-zA-Z0-9]+)?$") {
                Ok(r) => r,
                Err(_) => {
                    return Err(ErrorDetection::ValidationError {
                        message: "GenesisFile version validation failed".into(),
                        tx_id: None,
                    });
                }
            };

            if !semver_pattern.is_match(ver) {
                return Err(ErrorDetection::ValidationError {
                    message: format!("GenesisFile version has invalid format: {}", ver),
                    tx_id: None,
                });
            }
        } else {
            return Err(ErrorDetection::ValidationError {
                message: "GenesisFile version validation failed".into(),
                tx_id: None,
            });
        }

        // 3. Optionally check description (if present)
        if let Some(desc) = &self.description {
            if desc.trim().is_empty() {
                return Err(ErrorDetection::ValidationError {
                    message: "GenesisFile description is empty".into(),
                    tx_id: None,
                });
            }
            if desc.len() > 500 {
                return Err(ErrorDetection::ValidationError {
                    message: "GenesisFile description is too long (max 500 chars)".into(),
                    tx_id: None,
                });
            }
        }

        // 4. Validate the genesis block
        self.genesis_block.validate()?;

        Ok(())
    }

    /// Load and return the genesis block from a genesis.json path.
    /// Returns GenesisBlock directly, with all error mapping for ErrorDetection system.
    pub fn load_genesis_block_from_json(path: &str) -> Result<GenesisBlock, ErrorDetection> {
        let genesis_file = GenesisFile::from_json_file(path)?;
        // from_json_file already validates, but keep explicit intent here.
        genesis_file.validate()?;
        Ok(genesis_file.genesis_block)
    }
}
